"""Bounded asynchronous task manager with dependency waves, concurrency limits, and error isolation."""

import asyncio
import logging
from typing import Dict, List

from core.agent_base import BaseAgent
from core.context import InvestigationContext
from core.schemas import AgentResult, AgentRole, InvestigationTask, utc_now_iso

logger = logging.getLogger("FortiGateCore.TaskManager")


class BoundedTaskManager:
    """
    Dispatches specialist InvestigationTasks with:
    - Bounded concurrency via asyncio.Semaphore.
    - Dependency-wave scheduling (tasks with `depends_on` receive prior findings in `context_hints`).
    - Deterministic error/timeout isolation so one failing specialist never crashes the investigation.
    """

    def __init__(self, max_concurrency: int = 4):
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        self.max_concurrency = max_concurrency

    async def execute_tasks(
        self,
        tasks: List[InvestigationTask],
        agents_by_role: Dict[AgentRole, BaseAgent],
        context: InvestigationContext,
    ) -> List[AgentResult]:
        if not tasks:
            return []

        semaphore = asyncio.Semaphore(self.max_concurrency)
        completed_by_id: Dict[str, AgentResult] = {}
        remaining: Dict[str, InvestigationTask] = {t.task_id: t for t in tasks}
        ordered_results: List[AgentResult] = []

        async def _run_one(task: InvestigationTask) -> AgentResult:
            agent = agents_by_role.get(task.target_role)
            if agent is None:
                return AgentResult(
                    agent_name=f"MissingAgent({task.target_role.value})",
                    agent_role=task.target_role,
                    task_id=task.task_id,
                    correlation_id=task.correlation_id,
                    device=context.device,
                    vdom=context.vdom,
                    status="error",
                    summary=f"No specialist registered for role '{task.target_role.value}'.",
                    unknowns=[f"Role '{task.target_role.value}' was not registered."],
                    errors=[f"Unregistered role: {task.target_role.value}"],
                    started_at=utc_now_iso(),
                    completed_at=utc_now_iso(),
                )

            # Inject findings from satisfied dependency tasks
            if task.depends_on:
                prior = {}
                for dep_id in task.depends_on:
                    dep_res = completed_by_id.get(dep_id)
                    if dep_res is not None:
                        prior[dep_id] = {
                            "agent": dep_res.agent_name,
                            "status": dep_res.status,
                            "summary": dep_res.summary,
                            "findings": [f.model_dump() for f in dep_res.findings],
                        }
                task.context_hints["prior_findings"] = prior

            async with semaphore:
                try:
                    return await agent.arun(task, context)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.error("Unexpected error executing task %s: %s", task.task_id, exc)
                    return AgentResult(
                        agent_name=agent.name,
                        agent_role=agent.role,
                        task_id=task.task_id,
                        correlation_id=task.correlation_id,
                        device=context.device,
                        vdom=context.vdom,
                        status="error",
                        summary=f"Task execution crashed for {agent.name}.",
                        unknowns=[f"Unexpected execution failure in {agent.name}."],
                        errors=[str(exc)],
                        started_at=utc_now_iso(),
                        completed_at=utc_now_iso(),
                    )

        while remaining:
            ready = [
                t for t in remaining.values()
                if all(dep in completed_by_id for dep in t.depends_on)
            ]
            if not ready:
                # Cycle or unsatisfied external dependency — mark remaining tasks as errors deterministically
                for tid, task in list(remaining.items()):
                    err_res = AgentResult(
                        agent_name=f"Unscheduled({task.target_role.value})",
                        agent_role=task.target_role,
                        task_id=tid,
                        correlation_id=task.correlation_id,
                        device=context.device,
                        vdom=context.vdom,
                        status="error",
                        summary="Task could not be scheduled due to unsatisfied or cyclic dependencies.",
                        unknowns=["Unsatisfied task dependency graph."],
                        errors=[f"Unsatisfied dependencies: {task.depends_on}"],
                        started_at=utc_now_iso(),
                        completed_at=utc_now_iso(),
                    )
                    completed_by_id[tid] = err_res
                    ordered_results.append(err_res)
                    remaining.pop(tid)
                break

            context.record_trace(
                "task_wave_dispatch",
                {"wave_size": len(ready), "roles": [t.target_role.value for t in ready]},
            )
            wave_results = await asyncio.gather(*(_run_one(t) for t in ready))
            for task, res in zip(ready, wave_results):
                completed_by_id[task.task_id] = res
                ordered_results.append(res)
                remaining.pop(task.task_id, None)

        return ordered_results
