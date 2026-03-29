from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {"message": "EganPurple App is running 🚀"}

@app.get("/health")
def health():
    return {"status": "ok"}