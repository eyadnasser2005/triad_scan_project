import asyncio
from triad_scan.db import init_db, AsyncSessionLocal, AssetORM

async def main():
    await init_db()
    async with AsyncSessionLocal() as db:
        db.add_all([
            AssetORM(
                cpe_string="cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                confidentiality=9, integrity=9, availability=8
            ),
            AssetORM(
                cpe_string="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                confidentiality=8, integrity=8, availability=9
            ),
        ])
        await db.commit()
    print("Seeded assets.")

asyncio.run(main())
