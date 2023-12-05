from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import httpx


class CustomerData(BaseModel):
    enc_data: bytes


# Create an instance of the FastAPI class
app = FastAPI()
templates = Jinja2Templates(directory="templates")


# Define a simple endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/authcustomer")
async def handle_input(data: Request):
    receieved_data = await data.body()
    print(f"Received data from customer {receieved_data}")


# # Define an endpoint with a path parameter
# @app.get("/items/{item_id}")
# def read_item(item_id: int, query_param: str = None):
#     return {"item_id": item_id, "query_param": query_param}


# Run the server with uvicorn
# Use the command: uvicorn filename:app --reload
# For example, if your file is named "main.py", use: uvicorn main:app --reload
