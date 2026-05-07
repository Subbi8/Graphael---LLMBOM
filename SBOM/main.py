import os
import sys

from extractor import Extractor


def main(path,lang):
    if not os.path.exists(path):
        print(f"Path does not exist: {path}")
        return
    print(f"Analysing Path: {path}")

    project_name = os.path.basename(os.path.abspath(path)).replace(' ', '_')
    parent_result = os.path.dirname(os.path.abspath(__file__))
    result_dir = os.path.join(parent_result, f'result\\{project_name}')
    os.makedirs(result_dir, exist_ok=True)

    extractor = Extractor(lang,path,result_path=result_dir)
    extractor.extract()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python main.py <project_path> <lang>")
    else:
        if len(sys.argv) >= 3:
            main(sys.argv[1],sys.argv[2])
