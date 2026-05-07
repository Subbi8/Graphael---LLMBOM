import json
import os


class PhpExtractor:
    def __init__(self,path):
        self.path = path

    def extract_packages(self):
        """Looks for composer.json for packages otherwise uses vendor folder

        Returns:
            list<dict<{'category': list<packages>}>: packages -> {'name': '', 'version': '','vendor' : '', 'type': '', 'file':''}
        """
        composerfiles = []
        vendor_folder_path = ""
        for root,folders,files in os.walk(self.path):
            for folder in folders:
                if folder == "vendor":
                    vendor_path = os.path.join(root,folder)
                    vendor_folder_path = vendor_path
            for file in files:
                if file.lower() == "composer.json":
                    filepath = os.path.join(root,file)
                    composerfiles.append(filepath)
        if len(composerfiles) > 0:
            pass
            packages , build_packages = self._parse_composer_files(composerfiles)
            return [{'php':packages} , {'php_build_packages':build_packages}]
        else:
            if len(vendor_folder_path)>0:
                return [{'php':self._parse_vendor_folder(vendor_folder_path)}]
            else:
                print("Vendor folder or composer.json is not present")
                return [{'php':[]}]

    def _parse_composer_files(self,files_path):
        """parsing composer files to generate packages

        Args:
            files (list<(file,filepath)>): the filepaths where composer.json is present

        Returns:
            list<dict>: dict -> {'name': '', 'version': '','vendor' : '', 'type': '', 'file':''}
        """
        print(f"parsing composer file {files_path}")
        packages = []
        build_packages = []
        for path in files_path:
            try:
                with open(path,encoding="utf-8") as f:
                    content = json.load(f)
                    require = content.get("require",{})
                    require_dev = content.get("require-dev",{})
                    for lib,version in require.items():
                        vendor = "unknown"
                        if "/" in lib:
                            vendor,lib = lib.split("/",1)
                        packages.append({'name':lib, 'version':version , 'vendor':vendor,'type': 'requires','file':path})
                    for lib,version in require_dev.items():
                        vendor = "unknown"
                        if "/" in lib:
                            vendor,lib = lib.split("/",1)
                        build_packages.append({'name':lib , 'version':version , 'vendor':vendor,'type': 'build requires','file':path})
            except Exception as e:
                print(f"Exception {e} in parsing {path} :")
                return [] , []
        return packages , build_packages

    def _parse_vendor_folder(self,vendor_folder_path):
        """parses composer.json file which has a struture of
        vendor
            |->vendor name
                |->packages

        Args:
            vendor_folder_path (string): path to the vendor folder

        Returns:
            list<dict>: dict -> {'name': '', 'version': '','vendor' : '', 'type': '', 'file':''}
        """
        print(f"parsing vendor folder {vendor_folder_path}")
        packages = []
        try:
            for folder in os.listdir(vendor_folder_path):
                folder_path = os.path.join(vendor_folder_path,folder)
                if folder.lower() == "composer" or not os.path.isdir(folder_path):
                    continue
                if len(os.listdir(folder_path)) >= 1:
                    for sub_folder in os.listdir(folder_path):
                        packages.append({'name':sub_folder, 'version':'unknown' ,'vendor':folder,'type': 'requires','file':vendor_folder_path})
                else:
                    packages.append({'name':folder, 'version':'unknown' , 'vendor':'unknown','type':'requires','file':vendor_folder_path})
            return packages
        except Exception as e:
            print(f"Exception {e} in parsing {vendor_folder_path} :")
            return []
