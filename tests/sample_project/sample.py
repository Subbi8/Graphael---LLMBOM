from transformers import AutoModel
from datasets import load_dataset

def build_and_save():
    model = AutoModel.from_pretrained("gpt2", load_in_8bit=True)
    ds = load_dataset("wikitext", "wikitext-2-raw-v1")
    # pretend training
    model.save_pretrained("./out-model")

if __name__ == '__main__':
    build_and_save()
