import json
import os
import re


class DotnetExtractor:
    def __init__(self , path):
        self.path = path

    def extract_packages(self):
        """
    Traverse the project directory and extract package metadata from
    supported file types (e.g., .dll, .csproj, .cs, packages.config).

    Returns:
        list<dict>: A list containing a dictionary with the key 'dotnet' mapping to
              a list of package dictionaries with metadata.
        """
        packages = []
        for root, _,files in os.walk(self.path):
            for file in files:
                filepath = os.path.join(root,file)
                filename,ext = os.path.splitext(file)
                ext = ext.lower()
                file = file.lower()
                if ext == '.dll':
                    packages.append({'name':filename , 'version':"unknown",'vendor':'unknown','type':f'{ext[1:]}','file':filepath})
                elif ext == '.unitypackage':
                    packages.append({'name':filename , 'version':"unknown",'vendor':'unity','type':f'{ext[1:]}','file':filepath})
                elif file == 'manifest.json':
                    packages.extend(self._parse_manifest_files(filepath))
                elif ext == '.cs':
                    packages.extend(self._parse_cs_files(filepath))
                elif ext == '.csproj' or ext == '.fsproj':
                    packages.extend(self._parse_csproj_fsproj_file(filepath))
                elif ext == ".csx" or ext == '.fsx':
                    packages.extend(self._parse_csharp_fsharp_script_files(filepath))
                elif file == "packages.config":
                    packages.extend(self._parse_packages_config(filepath))
                elif file == "paket.dependencies":
                    packages.extend(self._parse_packet_dependencies_files(filepath))
        return [{'dotnet' :packages}]

    def _parse_csharp_fsharp_script_files(self,path):
        """
    Parse .csx or .fsx script files to extract package references using #r directives.

    Args:
        path (str): Path to the script file.

    Returns:
        list: List of dictionaries containing extracted package information such as
              name, version, vendor, type, and file path.
        """
        print(f"parsing csharp fsharp script file {path}")
        try:
            packages = []
            with open(path  , encoding="utf-8" , errors="ignore") as f:
                # content = f.read()
                for line in f:
                    line = line.strip()
                    if line.startswith("#r"):
                        # parsing: #r "nuget: Newtonsoft.Json, 13.0.1
                        pattern = re.search(r"\"nuget\s*:\s*(.*?)\s*\"",line,re.IGNORECASE)
                        if pattern:
                            name_and_verion = pattern.group(1)
                            if name_and_verion:
                                if "," in name_and_verion:
                                    lib , version = name_and_verion.split(",",1)
                                else:
                                    lib = name_and_verion
                                    version = "unknow"
                                packages.append({'name':lib, 'version':version , 'vendor':"nuget",'type': "package",'file':path})
                        #not including '#r "system.*" ' as they are framework and part of .net sdk and are not downloaded externally

                        #parsing: #r @"path/to.dll"
                        line_without_r = line.replace("#r","").strip()
                        if line_without_r.startswith("@"):
                            path_included = line_without_r.replace("@","").replace('"',"")
                            if "/" in path_included:
                                _ , file = path_included.split("/")
                            else:
                                file = path_included
                            packages.append({'name':file, 'version':"unknown" , 'vendor':"unknown",'type': 'file included','file':path})
            return packages
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    def _parse_packages_config(self,path):
        """
    Parse a NuGet `packages.config` XML file to extract package names and versions.

    Args:
        path (str): Path to the `packages.config` file.

    Returns:
        list: A list of dictionaries, each representing a NuGet package with the following keys:
              - name (str): Package name
              - version (str): Package version
              - vendor (str): Set to 'nuget'
              - type (str): Set to 'packages'
              - file (str): File path from which the package was extracted
        """
        print(f"parsing packages.config {path}")
        try:
            packages = []
            with open(path  , encoding="utf-8" , errors="ignore") as f:
                content = f.read()
                matches = re.finditer(r'<package\s+(.*?)>',content,re.IGNORECASE)
                for match in matches:
                    inner_content = match.group(1)
                    # <package id = "Newtonsoft.Json" version = "13.0.1" targetFramework="net48" />
                    #To remove the space between "="
                    inner_content = re.sub(r"\s*=\s*","=",inner_content)
                    name = "unknown"
                    version = "unknown"
                    if inner_content:
                        inner_content_array = inner_content.split()
                        for i in inner_content_array:
                            if '=' in i:
                                key,value = i.split("=",1)
                                if key.lower() == 'id':
                                    if '"' in value:
                                        value = value.replace('"' , "")
                                    name = value.strip()
                                elif key.lower() == 'version':
                                    if '"' in value:
                                        value = value.replace('"' , "")
                                    version = value.strip()
                    if name != "unknown":
                        packages.append({'name':name , 'version':version,'vendor':'nuget','type':"packages",'file':path})
            return packages
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    def _parse_packet_dependencies_files(self,path):
        """
    Parses a paket.dependencies file to extract NuGet and Git-based package dependencies.

    This function scans through the file specified by `path`, removes comments,
    normalizes key-value formatting, and extracts dependency names and versions
    from both `nuget` and `git` declarations. It attempts to remove non-essential
    metadata like `import_targets`, `build`, `os`, or hash values, and returns a
    list of structured dictionaries with extracted dependency metadata.

    Args:
        path (str): The full file path to the 'paket.dependencies' file.

    Returns:
        List[Dict[str, str]]: A list of dictionaries where each dictionary contains:
            - 'name': Name of the dependency.
            - 'version': Version constraint or 'unknown' if not specified.
            - 'vendor': Either 'nuget' or 'git' based on the source.
            - 'type': Always 'package'.
            - 'file': The original file path from which this dependency was parsed.

    Raises:
        None: Exceptions are caught internally and logged; returns an empty list on error.
        """
        print(f"parsing packet.dependencies {path}")
        try:
            packages = []
            with open(path  , encoding="utf-8" , errors="ignore") as f:
                content = f.read()
                #removes everything after // (removing comments)
                cleaned_content = re.sub(r'\s+//.*',"",content)
                matches = re.finditer(r'\s*nuget\s+(.*)',cleaned_content,re.IGNORECASE)
                for match in matches:
                    inner_content = match.group(1)
                    # print(inner_content)
                    #remove space between key and : and value
                    #Ex import_targets : false => import_targets:false
                    inner_content = re.sub(r'\s+:\s+',':',inner_content)
                    #Remove everything after and including key:
                    inner_content = re.sub(r'[^\s]*:.*','',inner_content)
                    #example
                    #content =  nuget Suave ~> 2.5 import_targets: false content: none
                    #inner_content = Suave ~> 2.5
                    inner_content_array = inner_content.split()
                    name = "unknown"
                    version = "unknown"
                    if len(inner_content_array) >= 1:
                        name = inner_content_array[0]
                        if len(inner_content_array) >= 2:
                            version = "".join(inner_content_array[1:])
                    if name != "unknown":
                        packages.append({
                            'name': name,
                            'version': version,
                            'vendor': 'nuget',
                            'type': 'package',
                            'file': path
                        })
                matches = re.finditer(r'\bgit\s+(.*)',cleaned_content,re.IGNORECASE)
                for match in matches:
                    inner_content = match.group(1)
                    inner_content = inner_content.lower()
                    #remove space between key and : and value
                    #Ex import_targets : false => import_targets:false
                    inner_content = re.sub(r'\s*:\s*',':',inner_content)
                    #Removeing build key value pair build:
                    inner_content = re.sub(r'\s+build\s*:\s*[^\s]+','',inner_content,re.IGNORECASE)
                    #Removeing os key value pair os :
                    inner_content = re.sub(r'\s+os\s*:\s*[^\s]+','',inner_content,re.IGNORECASE)
                    #Removing packages key value pair packages:
                    inner_content = re.sub(r'\s+packages\s*:\s*[^\s]+','',inner_content,re.IGNORECASE)
                    #Removing master keyword
                    #Here master is removed when it is either surrounded y space or the end of the line
                    inner_content = re.sub(r'\s+master(\s+|$)', '' , inner_content , re.IGNORECASE)
                    #Remove hashes
                    inner_content = re.sub(r'\b[0-9a-fA-F]{7,40}\b','',inner_content)
                    # print(inner_content)
                    inner_content_array = inner_content.split()
                    name = "unknown"
                    version = "unknown"
                    if len(inner_content_array) >= 1:
                        name = inner_content_array[0]
                        if len(inner_content_array) >= 2:
                            version = "".join(inner_content_array[1:])
                    if name != "unknown":
                        packages.append({
                            'name': name,
                            'version': version,
                            'vendor': 'git',
                            'type': 'package',
                            'file': path
                        })
                    # print(packages)
            return packages
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    def _parse_manifest_files(self,path):
        """
    Parses a manifest file (e.g., package.json or similar) to extract dependency information.

    This method loads a JSON file, typically containing a "dependencies" object, and extracts
    dependency names, versions, and optional vendor metadata. It also handles local file-based
    packages (e.g., 'file:../package.tgz') by extracting the version string from the filename.

    Args:
        path (str): The path to the manifest JSON file.

    Returns:
        List[Dict[str, str]]: A list of dictionaries where each dictionary contains:
            - 'name': Name of the dependency.
            - 'version': Version string extracted or derived.
            - 'vendor': Extracted vendor name or 'unknown' if not determinable.
            - 'type': Always set to "manifest".
            - 'file': The source file path.

    Notes:
        - Handles both direct version strings and 'file:' references.
        - Vendor is extracted as the second segment if the name contains a dot (e.g., 'com.vendor.pkg').
        """
        print(f"parsing mamifest file {path}")
        packages = []
        try:
            with open(path  , encoding= "utf-8",errors="ignore") as f:
                json_content = json.load(f)
                dependencies = json_content.get("dependencies", {})
                for key,value in dependencies.items():
                    vendor = 'unknown'
                    if '"' in key:
                        key = key.replace('"', "")
                    if '"' in value:
                        value = value.replace('"', "")
                    if '.' in key:
                        vendor = key.split('.')[1]
                    if value.startswith('file:'):
                        value = value.replace('file:' , '')
                        filename = os.path.basename(value)
                        file , ext = os.path.splitext(filename)
                        if ext == '.tgz':
                            version = file.replace(key,'')
                            if len(version) > 1:
                                if version[0] == '-' or version[0] == '@':
                                    version = version[1:]
                    else:
                        version = value
                    packages.append({'name':key , 'version':version,'vendor':vendor,'type':"manifest",'file':path})
            return packages
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    def _parse_csproj_fsproj_file(self,path):
        """
    Parses a `.csproj` or `.fsproj` file to extract NuGet package references.

    Args:
        path (str): Path to the `.csproj` or `.fsproj` file.

    Returns:
        list[dict]: A list of dictionaries, each representing a package with the following keys:
            - 'name': Package name
            - 'version': Package version (or 'unknown' if not found)
            - 'vendor': Set to 'nuget' as default
            - 'type': 'csproj'
            - 'file': File path
        """
        print(f"parsing csproj fsproj file {path}")
        # Example:
        # <PackageReference Version="13.0.3" Include="Newtonsoft.Json" PrivateAssets="all" />
        # <PackageReference Include="Newtonsoft.Json" PrivateAssets="all" Version="13.0.3" />
        packages = []
        try:
            with open(path  , encoding="utf-8",errors="ignore") as f:
                content = f.read()
                packages_content = re.finditer(r'<PackageReference\s+(.*?)>' ,content , re.IGNORECASE | re.DOTALL)
                for content in packages_content:
                    inner_content = content.group(1)
                    # print(inner_content)
                    # <package id = "Newtonsoft.Json" version = "13.0.1" targetFramework="net48" />
                    #To remove the space between "="
                    inner_content = re.sub(r"\s*=\s*","=",inner_content)
                    name = "unknown"
                    version = "unknown"
                    if inner_content:
                        inner_content_array = inner_content.split()
                        for i in inner_content_array:
                            if '=' in i:
                                key,value = i.split("=",1)
                                if key.lower() == 'include':
                                    if '"' in value:
                                        value = value.replace('"' , "")
                                    name = value.strip()
                                elif key.lower() == 'version':
                                    if '"' in value:
                                        value = value.replace('"' , "")
                                    if value.startswith('$('):
                                        value = "unknown"
                                    version = value.strip()
                    if name != "unknown":
                        packages.append({'name':name , 'version':version,'vendor':'nuget','type':"csproj",'file':path})
            return packages
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    def _parse_cs_files(self,path):

        """
    Parses `.cs` (C#) files to extract NuGet package information embedded as comments.

    Example lines expected in the file:
        #:package Humanizer@2.14.1

    Args:
        path (str): Path to the `.cs` source file.

    Returns:
        list: A list of dictionaries with extracted package information, where each dictionary contains:
              - name (str): Package name
              - version (str): Package version (or 'unknown' if not found)
              - vendor (str): Package vendor (assumed 'nuget' here)
              - type (str): The type of file parsed ('cs_file')
              - file (str): The original file path
        """
        print(f"parsing cs files {path}")
        packages = []
        try:
            with open(path,encoding="utf-8",errors="ignore") as f:
                content = f.read()
                matches = re.finditer(r'#:package\s+([^\s@]+)(?:@([^\s]+))?' , content , re.IGNORECASE)
                for match in matches:
                    name = match.group(1)
                    version = match.group(2) if match.group(2) else "unknown"
                    if name:
                        packages.append({'name':name , 'version':version,'vendor':'nuget','type':"cs_file",'file':path})
            return packages
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []
