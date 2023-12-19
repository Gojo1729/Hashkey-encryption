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

# Flows

<img width="695" alt="p1" src="https://github.com/Gojo1729/NSProject/assets/86954414/18003d84-f733-4a82-ad7b-0a668f44f1f8">
<img width="537" alt="p2" src="https://github.com/Gojo1729/NSProject/assets/86954414/1c6e6c9e-0776-4370-93b3-b946c65e1725">
<img width="566" alt="p3" src="https://github.com/Gojo1729/NSProject/assets/86954414/a83b1df3-1aa1-438c-b5a8-e771057bb39c">
<img width="926" alt="p4" src="https://github.com/Gojo1729/NSProject/assets/86954414/fbb21124-575d-466a-a57f-b3fce4a4c080">
<img width="716" alt="p5" src="https://github.com/Gojo1729/NSProject/assets/86954414/c87d4a72-b9fc-42cd-9b91-c8dd8784c85f">
