import csv
import json
import os

from c_cpp import C_CppExtractor
from dotnet import DotnetExtractor
from php import PhpExtractor
from python import PythonExtractor
from node import NodeExtractor
from standard_lib import STANDARD_C_LIBS, STANDARD_CPP_LIB


class Extractor:
    def __init__(self , lang,path,result_path):
        self.lang = lang.lower()
        self.path = path
        self.result_path = result_path
        self.extractor = self._get_lang_extractor()

    def _get_lang_extractor(self):
        """The extracator to use based on lang

        Returns:
            class : the class for the respective lang
        """
        if self.lang in ('c' ,'c++' , 'cpp'):
            return C_CppExtractor(self.path)

        if self.lang in ('csharp' , 'c#' , 'cs' , 'f#' , 'fsharp' , 'dotnet' , '.net'):
            return DotnetExtractor(self.path)

        if self.lang == "php":
            return PhpExtractor(self.path)

        if self.lang == "python":
            return PythonExtractor(self.path)

        if self.lang in ('javascript', 'js', 'typescript', 'ts', 'node', 'nodejs'):
            return NodeExtractor(self.path)

    def extract(self):
        """starting point which calls the respective functions to generate the sbom
        """
        extracted_packages = self.extractor.extract_packages()
        for extracted_pkg in extracted_packages:
            for category , packages in extracted_pkg.items():
                if len(packages) > 0:
                    packages = self._remove_duplicate_packages(packages)
                    self._generate_sbom(packages , category)

    def _remove_duplicate_packages(self,packages):
        """removes duplicate packages(based on name,version,vendor,name) and also removes built in packages like string.h from the packages

        Args:
            packages (list<dict>): dict -> {'name': '', 'version': '','vendor' : '', 'type': '', 'file':''}

        Returns:
            list<dict>: returns the unique list elements
        """
        seen = set()
        unique = []
        for pkg in packages:
            _,ext = os.path.splitext(pkg['file'])
            if ext == '.c' and pkg['name'] in STANDARD_C_LIBS:
                continue
            if ext == '.h' and pkg['name'] in STANDARD_C_LIBS:
                continue
            if ext == '.cpp' and pkg['name'] in STANDARD_CPP_LIB:
                continue
            key = (pkg['name'], pkg['version'], pkg['vendor'] , pkg['type'])
            if key not in seen:
                seen.add(key)
                unique.append(pkg)
        return unique

    def _generate_sbom(self,packages, file_name):
        """Generates csv and json based on packages

        Args:
            packages (list<dict>): dict -> {'name': '', 'version': '','vendor' : '', 'type': '', 'file':''}
            file_name (string): the string that has to be appeneded to the output file name
        """
        bom = {
            # "bomFormat": "CycloneDX",
            # "specVersion": "1.4",
            # "version": 1,
            "components": [
                {
                "name": pkg['name'].lower(),
                "version": pkg['version'],
                "publisher": pkg['vendor'],
                "file": pkg['file'],
                "type": pkg['type'],
                }
                    for pkg in packages
            ]
        }
        json_path = os.path.join(self.result_path, f"{file_name}_sbom.json")
        try:
            with open(json_path, 'w', encoding='utf-8',errors="ignore") as f:
                json.dump(bom, f, indent=2)
            print(f"SBOM JSON saved to: {json_path}")
        except Exception as e:
            print("error opening the file",e)

        csv_path = os.path.join(self.result_path, f"{file_name}_sbom.csv")
        try:
            with open(csv_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Name', 'Version', 'Vendor','file','type'])
                for pkg in packages:
                    writer.writerow([pkg['name'].lower(), pkg['version'], pkg['vendor'], pkg['file'],pkg['type']])

            print(f"SBOM CSV saved to: {csv_path}")
        except Exception as e:
            print("Error opening the file",e)
