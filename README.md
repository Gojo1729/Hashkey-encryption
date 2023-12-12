# NSProject

# Commands to run

python.exe -m uvicorn cust1_server:app --port 8001 --reload

python.exe -m uvicorn cust2_server:app --port 8004 --reload

python.exe -m uvicorn broker_server:app --port 8002 --reload

python.exe -m uvicorn merchant_server:app --port 8003 --reload

# Steps to execute

Customer1 mutually authenticates broker
broker sends session keys to customer1

Customer2 mutually authenticates broker
broker sends session keys to Customer2

broker mutually authenticates merchant
broker sends session keys to merchant

Customer1 authenticates merchant
Customer1 sends sessions keys to merchant

Customer2 authenticates merchant
Customer2 sends sessions keys to merchant

Customer1/Customer2 views product
Customer1/Customer2 buys product
Customer1/Custoemr2 accepts consent from broker

Money Transferred
