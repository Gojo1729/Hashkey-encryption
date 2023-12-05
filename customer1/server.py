from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import httpx


class CustomerInput(BaseModel):
    action_number: int
    enc_data: bytes


# Create an instance of the FastAPI class
app = FastAPI()
templates = Jinja2Templates(directory="templates")


# Define a simple endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/handleinput")
async def handle_input(action_number: int = Form(...)):
    print(f"Sending request to broker {action_number}")
    enc_data = b"\xb7\x11\x9e\xf7]\xf8v\xfe\x89n*\xb6\x96\x91\x8dWf\xaeb\xb0\x91s\n\x8b\x1do\xf8\xceV0\xc6k"

    # send auth request to broker
    if action_number == 1:
        result = {"action_number": action_number, "enc_data": enc_data}
        json_data = result
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://127.0.0.1:8002/authcustomer", content=enc_data
            )

        if response.status_code == 200:
            return {"message": "JSON request sent successfully"}
        else:
            raise HTTPException(
                status_code=response.status_code, detail="Failed to send JSON request"
            )

    # send auth request to merchant
    elif action_number == 2:
        return {"message": "Sending request to merchant"}
    # view products
    elif action_number == 3:
        pass

    # buy product
    elif action_number == 4:
        pass


# Define an endpoint with a path parameter
@app.get("/items/{item_id}")
def read_item(item_id: int, query_param: str = None):
    return {"item_id": item_id, "query_param": query_param}


# Run the server with uvicorn
# Use the command: uvicorn filename:app --reload
# For example, if your file is named "main.py", use: uvicorn main:app --reload
