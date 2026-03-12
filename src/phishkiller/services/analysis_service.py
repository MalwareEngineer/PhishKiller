"""Analysis result business logic."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from phishkiller.models.analysis_result import AnalysisResult


class AnalysisService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_results(
        self,
        offset: int = 0,
        limit: int = 50,
        kit_id: uuid.UUID | None = None,
        analysis_type: str | None = None,
    ) -> tuple[list[AnalysisResult], int]:
        query = select(AnalysisResult).order_by(AnalysisResult.created_at.desc())
        count_query = select(func.count(AnalysisResult.id))

        if kit_id:
            query = query.where(AnalysisResult.kit_id == kit_id)
            count_query = count_query.where(AnalysisResult.kit_id == kit_id)
        if analysis_type:
            query = query.where(AnalysisResult.analysis_type == analysis_type)
            count_query = count_query.where(
                AnalysisResult.analysis_type == analysis_type
            )

        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_result(self, result_id: uuid.UUID) -> AnalysisResult | None:
        result = await self.db.execute(
            select(AnalysisResult).where(AnalysisResult.id == result_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    def get_task_status(task_id: str) -> dict:
        from phishkiller.celery_app import celery_app

        result = celery_app.AsyncResult(task_id)
        response = {
            "task_id": task_id,
            "status": result.status,
            "result": None,
        }
        if result.ready():
            try:
                response["result"] = result.result
            except Exception:
                response["result"] = {"error": str(result.result)}
        return response
