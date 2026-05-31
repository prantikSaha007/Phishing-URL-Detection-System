import os
from pathlib import Path
from huggingface_hub import hf_hub_download

ARTIFACTS_DIR = Path(os.getenv("ARTIFACTS_DIR", "artifacts"))
HF_REPO = "Pranlos/phishguard-model"

def download_if_missing():
    ARTIFACTS_DIR.mkdir(exist_ok=True)

    model_path  = ARTIFACTS_DIR / "model.pkl"
    scaler_path = ARTIFACTS_DIR / "scaler.pkl"

    if not model_path.exists():
        print("Downloading model.pkl from Hugging Face...")
        path = hf_hub_download(repo_id=HF_REPO, filename="model.pkl")
        import shutil
        shutil.copy(path, model_path)

    if not scaler_path.exists():
        print("Downloading scaler.pkl from Hugging Face...")
        path = hf_hub_download(repo_id=HF_REPO, filename="scaler.pkl")
        import shutil
        shutil.copy(path, scaler_path)

if __name__ == "__main__":
    download_if_missing()