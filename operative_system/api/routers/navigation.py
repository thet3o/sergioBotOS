from fastapi import APIRouter

nav = APIRouter(
    prefix='/nav',
    tags=['navigation'],
    dependencies=[],
    responses=[]
)

@nav.get('/')
async def navigate():
    pass

@nav.post('/')
async def navigate():
    pass
