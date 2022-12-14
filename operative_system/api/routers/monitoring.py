from fastapi import APIRouter

monitor = APIRouter(
    prefix='/monitor',
    tags=['monitoring'],
    dependencies=[],
    responses=[]
)

@monitor.get('/')
async def monitoring():
    pass

@monitor.post('/')
async def monitoring():
    pass
