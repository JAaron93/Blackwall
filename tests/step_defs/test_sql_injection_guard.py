import pytest
from pytest_bdd import given, when, then, scenario
import aiosqlite
import asyncio

@scenario('../features/sql_injection_guard.feature', 'Prevent f-string dynamic SQL injection')
def test_prevent_sql_injection():
    pass

@given('an SQL injection payload', target_fixture='context')
def context():
    return {'payload': [1, "2) OR 1=1 --"], 'deleted': 0}

@when('the parameterized IN clause eviction query is executed')
def execute_query(context):
    async def run():
        candidate_ids = context['payload']
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("CREATE TABLE signatures (signature_id INT, match_count INT)")
            await db.execute("INSERT INTO signatures VALUES (1, 5), (2, 5), (3, 5)")

            chunk = candidate_ids
            placeholders = ",".join("?" * len(chunk))
            query = (
                "DELETE FROM signatures\n"
                f"WHERE signature_id IN ({placeholders})\n"
                "  AND match_count <= ?"
            )
            try:
                cursor = await db.execute(query, chunk + [10])
                context['deleted'] = cursor.rowcount if cursor.rowcount else 0
            except Exception as e:
                context['error'] = str(e)

            cursor = await db.execute("SELECT * FROM signatures")
            context['rows'] = await cursor.fetchall()

    asyncio.run(run())

@then('the SQL injection should fail and operate safely on candidates only')
def check_safety(context):
    # Only signature_id = 1 should be deleted if parameterized properly
    # "2) OR 1=1 --" should just fail to match any integer signature_id
    assert context['deleted'] == 1
    assert len(context['rows']) == 2
