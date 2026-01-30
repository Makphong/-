# Pccm-python 
<a href="[https://example.com](https://replit.com/@SuttipatKaewniw/Pccm-python)" target="_blank">
  <img src="https://img.shields.io/badge/Replit-DD1200?style=for-the-badge&logo=Replit&logoColor=white" />
</a>

รันบน Replit (สร้าง Packager files) 
1. สร้างโปรเจกต์ <br> ```bash uv init --no-progress --no-readme --no-pin-python --name repl_nix_workspace ```
2. ติดตั้ง Library <br> ``` uv add passlib fastapi uvicorn python-jose bcrypt python-multipart jinja2 jose starlette ```
3. ตั้งค่าให้ Library Passlib แมทช์กับ Bcrypt <br> ```pip uninstall -y bcrypt``` <br>  ```pip install -U "passlib==1.7.4" "bcrypt==4.0.1"```
4. กดปุ่มรัน


รันบน VS Code
1. ติดตั้ง Library <br> ```pip install passlib fastapi uvicorn python-jose bcrypt python-multipart jinja2 jose starlette```
3. ตั้งค่าให้ Library Passlib แมทช์กับ Bcrypt <br> ```pip uninstall -y bcrypt```  <br> ``` pip install -U "passlib==1.7.4" "bcrypt==4.0.1"```
4. รัน <br> ```uvicorn code:app --reload```

เพิ่มเติม(ทั้งคู่)
1. เช็คว่าตอนนี้เราติดตั้งไลบรารีอะไรอยู่บ้างเวอร์ชั่นอะไร <br> ```pip list```
