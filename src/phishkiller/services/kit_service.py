"""Kit business logic."""

import logging
import mimetypes
import shutil
import uuid
from pathlib import Path

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from phishkiller.config import get_settings
from phishkiller.models.analysis_result import AnalysisResult, AnalysisType
from phishkiller.models.associations import campaign_kits
from phishkiller.models.indicator import Indicator
from phishkiller.models.investigation import Investigation
from phishkiller.models.kit import Kit, KitStatus

logger = logging.getLogger(__name__)


class KitService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_kits(
        self,
        offset: int = 0,
        limit: int = 50,
        status_filter: str | None = None,
        source_feed: str | None = None,
    ) -> tuple[list[Kit], int]:
        query = select(Kit).order_by(Kit.created_at.desc())
        count_query = select(func.count(Kit.id))

        if status_filter:
            query = query.where(Kit.status == status_filter)
            count_query = count_query.where(Kit.status == status_filter)
        if source_feed:
            query = query.where(Kit.source_feed == source_feed)
            count_query = count_query.where(Kit.source_feed == source_feed)

        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_kit(self, kit_id: uuid.UUID) -> Kit | None:
        query = (
            select(Kit)
            .where(Kit.id == kit_id)
            .options(
                selectinload(Kit.indicators),
                selectinload(Kit.analysis_results),
                selectinload(Kit.campaigns),
                selectinload(Kit.child_kits),
            )
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def _find_existing_kit(self, url: str) -> Kit | None:
        """Find an existing non-FAILED kit with the same source URL."""
        query = select(Kit).where(
            Kit.source_url == url,
            Kit.status != KitStatus.FAILED,
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def submit_kit(
        self, url: str, source_feed: str | None = None
    ) -> tuple[Kit, str, bool]:
        # URL dedup: return existing kit if already tracked
        existing = await self._find_existing_kit(url)
        if existing:
            return existing, "", True

        kit = Kit(
            id=uuid.uuid4(),
            source_url=str(url),
            source_feed=source_feed or "manual",
            status=KitStatus.PENDING,
        )
        self.db.add(kit)
        await self.db.flush()

        # Dispatch Celery task
        from phishkiller.tasks.analysis import build_analysis_chain

        chain = build_analysis_chain(str(kit.id))
        result = chain.apply_async()
        task_id = result.id

        return kit, task_id, False

    async def submit_file(
        self,
        filename: str,
        local_path: str,
        source_feed: str | None = None,
        kit_id: uuid.UUID | None = None,
    ) -> tuple[Kit, str]:
        """Submit a locally-stored file for analysis (skip download)."""
        kit = Kit(
            id=kit_id or uuid.uuid4(),
            source_url=f"file://{filename}",
            source_feed=source_feed or "manual",
            local_path=local_path,
            filename=filename,
            status=KitStatus.PENDING,
        )
        self.db.add(kit)
        await self.db.flush()

        from phishkiller.tasks.analysis import build_analysis_chain

        chain = build_analysis_chain(str(kit.id))
        result = chain.apply_async()
        return kit, result.id

    async def submit_bulk(
        self, urls: list[str], source_feed: str | None = None
    ) -> tuple[list[dict], int, int]:
        """Submit multiple URLs. Returns (results, submitted, skipped)."""
        from phishkiller.tasks.analysis import build_analysis_chain

        results = []
        submitted = 0
        skipped = 0

        for url in urls:
            existing = await self._find_existing_kit(url)
            if existing:
                results.append({
                    "url": url,
                    "kit_id": existing.id,
                    "task_id": None,
                    "duplicate": True,
                })
                skipped += 1
                continue

            kit = Kit(
                id=uuid.uuid4(),
                source_url=url,
                source_feed=source_feed or "manual",
                status=KitStatus.PENDING,
            )
            self.db.add(kit)
            await self.db.flush()

            chain = build_analysis_chain(str(kit.id))
            task_result = chain.apply_async()
            results.append({
                "url": url,
                "kit_id": kit.id,
                "task_id": task_result.id,
                "duplicate": False,
            })
            submitted += 1

        return results, submitted, skipped

    async def submit_bulk_files(
        self, files: list[dict],
    ) -> list[dict]:
        """Submit multiple locally-stored files for analysis.

        Each entry in *files* must have: filename, local_path, kit_id.
        Returns a list of result dicts with kit_id and task_id.
        """
        from phishkiller.tasks.analysis import build_analysis_chain

        results: list[dict] = []
        for f in files:
            kit = Kit(
                id=f["kit_id"],
                source_url=f"file://{f['filename']}",
                source_feed="manual",
                local_path=f["local_path"],
                filename=f["filename"],
                status=KitStatus.PENDING,
            )
            self.db.add(kit)
            await self.db.flush()

            chain = build_analysis_chain(str(kit.id))
            task_result = chain.apply_async()
            results.append({
                "filename": f["filename"],
                "kit_id": kit.id,
                "task_id": task_result.id,
            })

        return results

    async def find_similar(
        self, kit_id: uuid.UUID, threshold: int = 100
    ) -> list[dict]:
        kit = await self.get_kit(kit_id)
        if not kit or not kit.tlsh:
            return []

        # Load all kits with TLSH hashes
        query = select(Kit).where(
            Kit.tlsh.isnot(None),
            Kit.id != kit_id,
        )
        result = await self.db.execute(query)
        candidates = result.scalars().all()

        similar = []
        try:
            import tlsh

            for candidate in candidates:
                distance = tlsh.diff(kit.tlsh, candidate.tlsh)
                if distance <= threshold:
                    similar.append({
                        "id": str(candidate.id),
                        "sha256": candidate.sha256,
                        "tlsh": candidate.tlsh,
                        "source_url": candidate.source_url,
                        "distance": distance,
                    })
            similar.sort(key=lambda x: x["distance"])
        except ImportError:
            pass

        return similar

    async def reanalyze(self, kit_id: uuid.UUID) -> str:
        kit = await self.get_kit(kit_id)
        if not kit:
            raise ValueError("Kit not found")

        kit.status = KitStatus.PENDING
        await self.db.flush()

        from phishkiller.tasks.analysis import build_analysis_chain

        chain = build_analysis_chain(str(kit.id))
        result = chain.apply_async()
        return result.id

    async def _collect_descendant_ids(self, kit_id: uuid.UUID) -> list[uuid.UUID]:
        """Recursively collect all descendant kit IDs (depth-first)."""
        all_ids: list[uuid.UUID] = []

        async def _recurse(parent_id: uuid.UUID) -> None:
            result = await self.db.execute(
                select(Kit.id).where(Kit.parent_kit_id == parent_id)
            )
            child_ids = [row[0] for row in result.all()]
            for cid in child_ids:
                all_ids.append(cid)
                await _recurse(cid)

        await _recurse(kit_id)
        return all_ids

    async def get_deletion_preview(self, kit_id: uuid.UUID) -> dict | None:
        """Return a summary of everything that will be cascade-deleted."""
        kit = await self.get_kit(kit_id)
        if not kit:
            return None

        descendant_ids = await self._collect_descendant_ids(kit_id)
        all_kit_ids = [kit_id] + descendant_ids

        indicator_count = (await self.db.execute(
            select(func.count()).select_from(Indicator).where(
                Indicator.kit_id.in_(all_kit_ids)
            )
        )).scalar_one()

        analysis_count = (await self.db.execute(
            select(func.count()).select_from(AnalysisResult).where(
                AnalysisResult.kit_id.in_(all_kit_ids)
            )
        )).scalar_one()

        campaign_link_count = (await self.db.execute(
            select(func.count()).select_from(campaign_kits).where(
                campaign_kits.c.kit_id.in_(all_kit_ids)
            )
        )).scalar_one()

        investigation_count = (await self.db.execute(
            select(func.count()).select_from(Investigation).where(
                Investigation.root_kit_id.in_(all_kit_ids)
            )
        )).scalar_one()

        return {
            "kit_id": str(kit_id),
            "total_kits": len(all_kit_ids),
            "child_kits": len(descendant_ids),
            "indicators": indicator_count,
            "analysis_results": analysis_count,
            "campaign_links": campaign_link_count,
            "investigations": investigation_count,
        }

    async def get_kit_content(
        self, kit_id: uuid.UUID, max_file_size: int = 1_048_576
    ) -> list[dict] | None:
        """Read text content from the kit's extracted files (or raw download)."""
        kit = await self.get_kit(kit_id)
        if not kit:
            return None

        settings = get_settings()
        files: list[dict] = []

        # Scannable text extensions
        text_exts = {
            ".html", ".htm", ".php", ".js", ".css", ".json", ".xml",
            ".txt", ".eml", ".py", ".sh", ".bat", ".ps1", ".vbs",
            ".svg", ".yml", ".yaml", ".ini", ".conf", ".cfg", ".htaccess",
        }

        # MIME types that indicate readable text content
        text_mimes = {
            "text/html", "text/plain", "text/css", "text/xml",
            "application/json", "application/xml", "application/javascript",
            "application/x-php", "message/rfc822",
        }

        def _is_text_file(fp: Path, kit_mime: str | None = None) -> bool:
            """Check if a file is likely text content."""
            if fp.suffix.lower() in text_exts:
                return True
            # No extension — check kit MIME type or sniff content
            if not fp.suffix:
                if kit_mime and kit_mime in text_mimes:
                    return True
                # Sniff first 512 bytes for text content
                try:
                    head = fp.read_bytes()[:512]
                    # If it decodes as UTF-8 and looks like HTML/JS/text, it's text
                    head.decode("utf-8")
                    return True
                except (OSError, UnicodeDecodeError):
                    return False
            return False

        def _read_file(fp: Path, relative_to: Path | None = None) -> dict | None:
            try:
                size = fp.stat().st_size
                truncated = size > max_file_size
                content = fp.read_text(errors="replace")[:max_file_size]
                mime, _ = mimetypes.guess_type(fp.name)
                # Fall back to the kit's stored MIME type for extension-less files
                if not mime and not fp.suffix and kit.mime_type:
                    mime = kit.mime_type
                filename = str(fp.relative_to(relative_to)) if relative_to else fp.name
                return {
                    "filename": filename,
                    "content": content,
                    "size": size,
                    "mime_type": mime,
                    "truncated": truncated,
                }
            except (OSError, UnicodeDecodeError):
                return None

        # Check extracted directory first
        extract_dir = Path(settings.kit_extract_dir) / str(kit_id)
        if extract_dir.is_dir():
            for fp in sorted(extract_dir.rglob("*")):
                if not fp.is_file():
                    continue
                if not _is_text_file(fp):
                    continue
                if len(files) >= 50:
                    break
                entry = _read_file(fp, relative_to=extract_dir)
                if entry:
                    files.append(entry)

        # Fallback: raw downloaded file
        if not files and kit.local_path:
            raw = Path(kit.local_path)
            if raw.is_file() and _is_text_file(raw, kit.mime_type):
                entry = _read_file(raw)
                if entry:
                    files.append(entry)

        return files

    async def search_kits(
        self,
        q: str | None = None,
        yara_rule: str | None = None,
        tlsh_hash: str | None = None,
        tlsh_threshold: int = 100,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[dict], int]:
        """Search kits by text, YARA rule name, or TLSH similarity."""

        # TLSH similarity search (different path — needs in-memory comparison)
        if tlsh_hash:
            return await self._search_by_tlsh(tlsh_hash, tlsh_threshold, offset, limit)

        # YARA rule search — JSONB query on analysis_results
        if yara_rule:
            return await self._search_by_yara(yara_rule, offset, limit)

        # General text search
        if q:
            return await self._search_by_text(q, offset, limit)

        return [], 0

    async def _search_by_text(
        self, q: str, offset: int, limit: int
    ) -> tuple[list[dict], int]:
        pattern = f"%{q}%"
        where = or_(
            Kit.source_url.ilike(pattern),
            Kit.sha256.ilike(pattern),
            Kit.md5.ilike(pattern),
            Kit.sha1.ilike(pattern),
            Kit.tlsh.ilike(pattern),
            Kit.filename.ilike(pattern),
        )
        count_q = select(func.count(Kit.id)).where(where)
        total = (await self.db.execute(count_q)).scalar_one()

        query = select(Kit).where(where).order_by(Kit.created_at.desc()).offset(offset).limit(limit)
        result = await self.db.execute(query)
        kits = result.scalars().all()
        return [self._kit_to_summary(k) for k in kits], total

    async def _search_by_yara(
        self, rule_name: str, offset: int, limit: int
    ) -> tuple[list[dict], int]:
        """Find kits where a YARA rule matched (JSONB query on analysis_results)."""
        # analysis_results.result_data->'matches' is an array of objects with 'rule' key
        from sqlalchemy import text

        # Count
        count_sql = text("""
            SELECT COUNT(DISTINCT k.id)
            FROM kits k
            JOIN analysis_results ar ON ar.kit_id = k.id
            WHERE ar.analysis_type = 'yara_scan'
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(ar.result_data->'matches') m
                WHERE m->>'rule' ILIKE :pattern
              )
        """)
        pattern = f"%{rule_name}%"
        total = (await self.db.execute(count_sql, {"pattern": pattern})).scalar_one()

        # Fetch
        fetch_sql = text("""
            SELECT DISTINCT k.id, k.source_url, k.sha256, k.tlsh, k.status,
                   k.file_size, k.source_feed, k.created_at
            FROM kits k
            JOIN analysis_results ar ON ar.kit_id = k.id
            WHERE ar.analysis_type = 'yara_scan'
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(ar.result_data->'matches') m
                WHERE m->>'rule' ILIKE :pattern
              )
            ORDER BY k.created_at DESC
            OFFSET :offset LIMIT :limit
        """)
        rows = (await self.db.execute(
            fetch_sql, {"pattern": pattern, "offset": offset, "limit": limit}
        )).mappings().all()

        items = [
            {
                "id": str(r["id"]),
                "source_url": r["source_url"],
                "sha256": r["sha256"],
                "tlsh": r["tlsh"],
                "status": r["status"],
                "file_size": r["file_size"],
                "source_feed": r["source_feed"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
        return items, total

    async def _search_by_tlsh(
        self, tlsh_hash: str, threshold: int, offset: int, limit: int
    ) -> tuple[list[dict], int]:
        """Find kits similar to the given TLSH hash."""
        query = select(Kit).where(Kit.tlsh.isnot(None))
        result = await self.db.execute(query)
        candidates = result.scalars().all()

        similar: list[dict] = []
        try:
            import tlsh

            for kit in candidates:
                distance = tlsh.diff(tlsh_hash, kit.tlsh)
                if distance <= threshold:
                    d = self._kit_to_summary(kit)
                    d["distance"] = distance
                    similar.append(d)
            similar.sort(key=lambda x: x["distance"])
        except ImportError:
            pass

        total = len(similar)
        return similar[offset : offset + limit], total

    @staticmethod
    def _kit_to_summary(kit: Kit) -> dict:
        return {
            "id": str(kit.id),
            "source_url": kit.source_url,
            "sha256": kit.sha256,
            "tlsh": kit.tlsh,
            "status": kit.status.value if hasattr(kit.status, "value") else str(kit.status),
            "file_size": kit.file_size,
            "source_feed": kit.source_feed,
            "created_at": kit.created_at.isoformat() if kit.created_at else None,
        }

    async def delete_kit(self, kit_id: uuid.UUID) -> bool:
        """Delete a kit and all its descendants (DB cascades handle FK cleanup)."""
        kit = await self.get_kit(kit_id)
        if not kit:
            return False

        # Collect local file paths for cleanup before the rows disappear
        local_paths: list[str] = []
        if kit.local_path:
            local_paths.append(kit.local_path)

        descendant_ids = await self._collect_descendant_ids(kit_id)
        if descendant_ids:
            result = await self.db.execute(
                select(Kit.local_path).where(
                    Kit.id.in_(descendant_ids),
                    Kit.local_path.isnot(None),
                )
            )
            local_paths.extend(row[0] for row in result.all())

        # DB cascades delete children, indicators, analysis_results,
        # campaign_kits rows, and investigations (if root_kit)
        await self.db.delete(kit)

        # Best-effort file cleanup (after ORM marks for deletion)
        for path in local_paths:
            try:
                kit_dir = Path(path).parent
                if kit_dir.exists():
                    shutil.rmtree(kit_dir)
            except OSError:
                logger.warning("Failed to clean up kit files at %s", path)

        return True
