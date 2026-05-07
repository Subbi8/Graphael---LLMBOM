import json
import os
import re

import requests
from ddgs import DDGS


class C_CppExtractor:
    def __init__(self,path):
        self.i = -1
        self.path = path

    def extract_packages(self):
        """
        Extracts C/C++ related package metadata and header dependencies from files
        across various build systems and packaging formats.

        Returns:
            list<dict>: A list of three dictionaries:
            - {'c_cpp_packages': list of detected runtime/source packages}
            - {'build_packages': list of detected build-time dependencies}
            - {'header_files': list of included header files from source code}
        """
        packages = []
        header = []
        build_packages = []
        for root, _,files in os.walk(self.path):
            for file in files:
                filepath = os.path.join(root,file)
                filename,ext = os.path.splitext(file)
                if file.lower() == "control":
                    package_file_packages , package_file_build_packages = self._parse_debian_control(filepath)
                    packages.extend(package_file_packages)
                    build_packages.extend(package_file_build_packages)
                elif file.lower() == "apkbuild":
                    package_file_packages , package_file_build_packages = self._parse_alpine_apkbuild(filepath)
                    packages.extend(package_file_packages)
                    build_packages.extend(package_file_build_packages)
                elif file.lower() == "pkgbuild":
                    package_file_packages , package_file_build_packages = self._parse_arch_pkgbuild(filepath)
                    packages.extend(package_file_packages)
                    build_packages.extend(package_file_build_packages)
                elif ext == '.spec':
                    package_file_packages , package_file_build_packages = self._parse_rpm_spec(filepath)
                    packages.extend(package_file_packages)
                    build_packages.extend(package_file_build_packages)
                elif file.lower() == 'cmakelists.txt':
                    packages.extend(self._parse_cmake_file(filepath))
                elif file.lower() == "configure.ac":
                    packages.extend(self._parse_configure_ac(filepath))
                elif filename.lower() == 'makefile' and file.lower() != "makefile.in":
                    packages.extend(self._parse_makefile(filepath))
                elif file.lower() == "meson.build":
                    packages.extend(self._parse_meson_file(filepath))
                elif file.lower() == "vcpkg.json":
                    packages.extend(self._parse_vcpkg_file(filepath))
                elif ext in ('.c' , '.h' , 'hpp' , '.cpp'):
                    header.extend(self._parse_header_files(filepath))
        #key is part of the file name
        return [{'c_cpp_packages':packages} , {'build_packages': build_packages} , {'header_files':header}]

    def _parse_debian_control(self,path):
        print(f"parsing control file {path}")
        """
        Parses a Debian 'control' file to extract runtime and build-time dependencies.

        Args:
            path (str): Path to the control file.

        Returns:
            tuple: A tuple containing:
            - list of runtime packages (from 'Depends')
            - list of build-time packages (from 'Build-Depends')
        """
        depends = ""
        build_depends = ""
        try:
            with open(path,encoding='utf-8',errors="ignore") as f:
                current_key=""
                for line in f:
                    line = line.rstrip('\n')
                    if not line.strip():
                        continue
                    #to ignore comments
                    if line[0] == '#':
                        continue
                    if ":" in line:
                        current_key,value = line.split(':',1)
                        # in control file feild names are not case sensitive so
                        # Depends == depends == DEPENDS
                        current_key = current_key.lower()
                        #if the file contains multible depends then it concatinates the line after adding ","
                        if current_key == 'depends':
                            if depends != "":
                                depends += ","
                            depends += value.strip()

                        elif current_key == 'build-depends' or current_key == 'pre-depends':
                            if build_depends != "":
                                build_depends += ","
                            build_depends += value.strip()
                    else:
                        if current_key == 'depends':
                                depends += line.strip()
                        elif current_key == 'build-depends' or current_key == 'pre-depends':
                                build_depends += line.strip()

            if '(' in depends:
                depends = depends.replace('(' , "")
            if ')' in depends:
                depends = depends.replace(')' , "")
            if '(' in build_depends:
                build_depends = build_depends.replace("(", "")
            if ')' in build_depends:
                build_depends = build_depends.replace(')',"")
            if "," in depends:
                depends = depends.replace(",", " ")
            if "," in build_depends:
                build_depends = build_depends.replace(",", " ")
            return  self._list_from_string(require_string=depends , type_string="package", path=path, vendor="debian", ),self._list_from_string(require_string=build_depends , type_string="build package",path=path,vendor="debian")
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")

    def _parse_rpm_spec(self,path):
        """
    Parses an RPM .spec file to extract runtime and build-time dependencies.

    Args:
        path (str): Path to the RPM spec file.

    Returns:
        Tuple[List[Dict], List[Dict]]: A tuple containing two lists of parsed package information:
            - First list for runtime requirements (`Requires`)
            - Second list for build-time requirements (`BuildRequires`)
            Each entry is a dictionary as returned by `self._list_from_string`.
        """
        print(f"parsing spec file {path}")
        requires = ""
        build_requires = ""
        try:
            with open(path,encoding='utf-8',errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line[0] == '#':
                        continue
                    if ":" in line:
                        key,value = line.split(":" , 1)
                        key = key.lower()
                        # Requires(preun):
                        # Requires(post):
                        # Requires(preun):
                        # Requires(post):
                        # Requires(postun):
                        # Requires(postun):
                        if "buildrequires" == key or key.startswith("requires("):
                            value = value.strip()
                            #as value can be comma or space seperated
                            if "," in value:
                                value =value.replace(","," ")
                                #to remove double spaces
                                value = " ".join(value.split())
                            #BuildRequires:pkgconfig(json-c)
                            #BuildRequires:pkgconfig(libmicrohttpd)
                            #to handle the above case
                            if value.startswith("pkgconfig(") and value.endswith(")"):
                                value = value.replace("pkgconfig(","")
                                value = value[:-1]
                            if build_requires != "":
                                build_requires = build_requires + " "
                            build_requires = build_requires + value
                        elif "requires" == key:
                            value = value.strip()
                            #as value can be comma or space seperated

                            if "," in value:
                                value =value.replace(","," ")
                                #to remove double spaces
                                value = " ".join(value.split())
                            if requires != "":
                                requires = requires + " "
                            # Requires:pkgconfig(json-c)
                            # Requires:pkgconfig(libmicrohttpd)
                            #to handle the above case
                            if value.startswith("pkgconfig(") and value.endswith(")"):
                                value = value.replace("pkgconfig(","")
                                value = value[:-1]
                            requires = requires + value

            return self._list_from_string(require_string=requires.strip(),type_string="package",path=path,vendor="redhat"), self._list_from_string(require_string=build_requires.strip(),type_string="build package",path=path,vendor="redhat")
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")

    def _parse_arch_pkgbuild(self,path):
        """
    Parses an Arch Linux PKGBUILD file to extract runtime (`depends`)
    and build-time (`makedepends`) dependencies.

    Args:
        path (str): Path to the PKGBUILD file.

    Returns:
        Tuple[List[Dict], List[Dict]]: A tuple of two lists containing:
            - Runtime dependencies from `depends`
            - Build-time dependencies from `makedepends`
        Each list contains dictionaries as returned by `self._list_from_string`.
        """
        depends = ""
        make_depends = ""
        print(f"parsing PKGBUILD {path}")
        try:
            with open(path,encoding='utf-8',errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line[0] == '#':
                        continue
                    if "=" in line:
                        key,value = line.split("=",1)
                        if key == "depends":
                            value = value.strip()
                            if len(value) > 2:
                                if value[0] == '(' and value[-1] == ')':
                                    depends += value[1:-1]
                        elif key == "makedepends":
                            value = value.strip()
                            if len(value) > 2:
                                if value[0] == '(' and value[-1] == ')':
                                    make_depends += value[1:-1]
            if "'" in depends:
                depends = depends.replace("'", " ")
            if '"' in depends:
                depends = depends.replace('"' , ' ')
            if "'" in make_depends:
                make_depends = make_depends.replace("'"," ")
            if '"' in make_depends:
                make_depends = make_depends.replace('"',' ')
            depends = " ".join(depends.split())
            make_depends = " ".join(make_depends.split())
            return self._list_from_string(require_string=depends ,type_string="package",path=path,vendor="archlinux") , self._list_from_string(require_string=make_depends,type_string="build package",path=path,vendor="archlinux")
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    def _parse_alpine_apkbuild(self,path):
        """
    Parses an Alpine Linux APKBUILD file to extract runtime (`depends`)
    and build-time (`makedepends`) dependencies.

    Args:
        path (str): Path to the APKBUILD file.

    Returns:
        Tuple[List[Dict], List[Dict]]: A tuple of two lists:
            - Runtime dependencies from `depends`
            - Build-time dependencies from `makedepends`
        Each list contains dictionaries as returned by `self._list_from_string`.
        """
        print(f"parsing apkbuild {path}")
        depends = ""
        makedepends = ""
        try:
            with open(path,encoding="utf-8",errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line[0] == '#':
                        continue
                    if "=" in line:
                        key,value = line.split("=", 1)
                        if key == "depends":
                            value = value.strip()
                            if len(value) > 2 and value.startswith('"') and value.endswith('"'):
                                value = value[1:-1]
                                depends = depends+value
                        elif key == "makedepends" :
                            value = value.strip()
                            #to remove quotes from value
                            if len(value) > 2 and value.startswith('"') and value.endswith('"'):
                                value = value[1:-1]
                                makedepends += value
            return self._list_from_string(require_string=depends,type_string="package",path=path,vendor="alpine") , self._list_from_string(require_string=makedepends,type_string= "build package",path=path,vendor="alpine")
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    def _parse_vcpkg_file(self,path):
        print(f"parsing vcpkg {path}")
        """
        Parses a `vcpkg.json` file to extract dependencies and overrides.

        Args:
            path (str): Path to the vcpkg.json file.

        Returns:
            List[Dict]: A list of dictionaries representing packages with keys:
            - 'name': Name of the package
            - 'version': Extracted version or version constraint
            - 'vendor': Always set to 'unknown' (can be improved later)
            - 'type': Always 'package'
            - 'file': Path to the source file
        """
        try:
            parsed_pack = []
            with open(path,encoding="utf-8",errors="ignore") as f:
                data = json.load(f)
                dependencies = data.get("dependencies",[])
                for dep in dependencies:
                    if isinstance(dep,str):
                        vendor = self.get_vendor(dep)
                        parsed_pack.append({'name':dep , 'version':"unknown",'vendor':vendor,'type':"package",'file':path})
                    if isinstance(dep,dict):
                        name = dep.get("name")
                        version = "unknown"
                        #As key are of the form version>= :, version<= :
                        for k,v in dep.items():
                            if k.lower() in ("version" , "version-string" , "version-date" , "version-semver"):
                                version = v
                            elif k.lower() == "version>=":
                                version = f">={v}"
                        vendor = self.get_vendor(name)
                        parsed_pack.append({'name':name , 'version':version,'vendor':vendor,'type':"package",'file':path})
                overrides = data.get("overrides",[])
                for dep in overrides:
                    name = dep.get("name")
                    version = dep.get("version")
                    updated = False
                    for i in parsed_pack:
                        if i['name'] == name:
                            i['version'] = version
                            updated = True
                    if not updated:
                        vendor = self.get_vendor(name)
                        parsed_pack.append({'name':name , 'version':version,'vendor':'unknown','type':"package",'file':path})
            return parsed_pack
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    def _parse_header_files(self,path):
        """
    Parses a C/C++ source or header file to extract included headers.

    Args:
        path (str): Path to the .c/.cpp/.h/.hpp file.

    Returns:
        List[Dict]: A list of dictionaries, each representing an included header file with:
            - 'name': Header name (e.g., stdio.h or mylib.hpp)
            - 'version': Always 'unknown' (can be extended later)
            - 'vendor': Always 'unknown' (can be inferred later)
            - 'type': Always 'headers'
            - 'file': Path of the file where the header was found
        """
        headers = []
        try:
            with open(path,encoding='utf-8', errors="ignore") as f:
                content = f.read()
                includes = re.finditer(r'#include\s+[<\"](.*?)[>\"]', content)
                for libs in includes:
                    lib = libs.group(1)
                    headers.append({'name':lib , 'version':"unknown",'vendor':'unknown','type':"headers",'file':path})
            return headers
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    #for pkgbuild and apkbuild
    def _extract_value_form_variable(self,path,variable):
        """
    Extracts the value assigned to a specific variable in pkgbuild and apkbuild file using regex.
    Args:
        path (str): Path to the file containing the variable assignment.
        variable (str): Name of the variable to extract.

    Returns:
        str or None: The value assigned to the variable as a string (may include quotes or parentheses),
                     or None if the variable is not found.
        """
        with open(path,encoding="utf-8" , errors='ignore') as f:
            content = f.read()
            match = re.search(rf'{re.escape(variable)}\s*=\s*(.*)',content)
            if match:
                return match.group(1)
            return None

    def _extract_value_from_variable_spec(self,path,variable):
        """
    Extracts the value(s) assigned to a `%define` variable in an RPM `.spec` file
    and returns their common prefix.

    Args:
        path (str): Path to the RPM spec file.
        variable (str): Name of the `%define` variable to search for.

    Returns:
        str: Common prefix of all matched values, or an empty string if no match is found.
        """
        with open(path,encoding="utf-8" , errors='ignore') as f:
            content = f.read()
            matches = re.finditer(rf'%define\s+{re.escape(variable)}\s+(.*)',content)
            values = [m.group(1).strip() for m in matches]
            prefix = os.path.commonprefix(values)
            return prefix

    def _list_from_string(self,require_string,type_string,path,vendor='unknown'):
        """
    Parses a space-separated string of dependencies into a structured list of dicts,
    extracting names and versions while resolving embedded variable references.

    Args:
        require_string (str): Raw dependency string (e.g., "gcc >= 9.0 libxml2>=2.9").
        type_string (str): Type of dependency (e.g., "package", "build package").
        vendor (str): Vendor or platform name (e.g., "debian", "redhat").
        path (str): Path to the source file containing the dependency info.

    Returns:
        List[Dict]: A list of structured dependency metadata dictionaries.
        """
        if not require_string:
            return []
        #if the string has or("|") then it is just replacing it currently so both can be included
        require_string = require_string.replace("|"," ")
        parsed = []
        i = 0
        tokens = require_string.split()
        file = os.path.basename(path)
        while i < len(tokens):
            token = tokens[i]
            if len(token) <= 1:
                i=i+1
                continue
            if file.lower() == 'control':
                #control file does not contain variables these are for ${misc:depends}
                if token[0] == '$' or token[0] == '%':
                    i=i+1
                    continue
            # print(token)
            next_value = False

            pattern = r'\%\{(.*?)\}'  # non-greedy match
            matches = re.findall(pattern, token)
            for var in matches:
                value = self._extract_value_from_variable_spec(path, var)
                if value:
                    token = token.replace(f"%{{{var}}}", value)
                else:
                    next_value = True
                    break

            pattern = r'\$\{(.*?)\}'
            matches = re.findall(pattern, token)
            for var in matches:
                value = self._extract_value_form_variable(path, var)
                if value:
                    token = token.replace(f"${{{var}}}", value)
                else:
                    next_value = True
                    break

            if next_value :
                i=i+1
                continue

            if token[0] == "<" or token[0] == "[" or token[0] == "@":
                i+=1
                continue
            if token[-1] == ']' or token[-1] == '>' or token[-1] == '%':
                i=i+1
                continue
            if token[0] == "'" and token[-1] == "'":
                token = token[1:-1]
            if token[0] == '"' and token[-1] == '"':
                token = token[1:-1]


            # Case 1: Match embedded operator (like 'perl-deve>9.2')
            # Example: perl-devel>=9.2
            # Example: perl-devel<9.2
            match = re.match(r'^([^\s><=]+)(>=|<=|=|>|<)([\w\.\-_~+:#]+)$', token)
            if match:
                name, op, ver = match.groups()
                if vendor.lower() == 'unknown':
                    vendor = self.get_vendor(name)
                parsed.append({'name':name , 'version':f"{op}{ver}",'vendor':vendor,'type':type_string,'file':path})
                i += 1
                continue
            if i+2 < len(tokens):
                #Case 2 Match space between the operater and the version number and name
                #Example: gcc >= 9.0
                #Example: gcc <= 3.4
                #gcc => token
                #>= => token[i+1]
                #9.0 => token[i+2]
                if re.match(r'^(>=|<=|=|>|<)$',tokens[i + 1]) and re.match(r'^[\w\.\-_~+:#]+$', tokens[i + 2]):
                    if vendor.lower() == 'unknown':
                        vendor = self.get_vendor(token)
                    parsed.append({'name':token , 'version':f"{tokens[i + 1]}{tokens[i + 2]}",'vendor':vendor,'type':type_string,'file':path})
                    i += 3
                    continue
            if i+1<len(tokens):
                #case 3: Match the space between name and operator no space between operator and version number
                #Example: gcc >=9.0
                #gcc => token
                #>=9.0 => token[i+1]
                if re.match(r'^(>=|<=|=|>|<)[\w\.\-_~+:#]+$', tokens[i + 1]):
                    if vendor.lower() == 'unknown':
                        vendor = self.get_vendor(token)
                    parsed.append({'name':token , 'version':tokens[i + 1],'vendor':vendor,'type':type_string,'file':path})
                    i+=2
                    continue
                #first match is the name and second match is the symbol(>=,<=,=,>,<)
                #case 3: Match the space between operator and version no space between name and operator
                #Example: gcc>= 9.0
                #gcc>= => token
                #9.0 => token[i+1]
                match_text_symbol = re.match(r'^([^\s><=]+)(>=|<=|=|>|<)$',token)
                match_version = re.match(r'^[\w\.\-_~]+$', tokens[i + 1])
                if match_text_symbol and match_version:
                    text , symbols = match_text_symbol.groups()
                    if vendor.lower() == 'unknown':
                        vendor = self.get_vendor(text)
                    parsed.append({'name':text , 'version':f"{symbols}{tokens[i + 1]}",'vendor':vendor,'type':type_string,'file':path})
                    i += 2
                    continue
            if vendor.lower() == 'unknown':
                vendor = self.get_vendor(token)
            parsed.append({'name':token , 'version':'unknown','vendor':vendor,'type':type_string,'file':path})
            i+=1
        return parsed

    def _parse_makefile(self,path):
        """
    Parses a Makefile to extract statically linked libraries.

    Args:
        path (str): Path to the Makefile.

    Returns:
        list[dict]: A list of dictionaries containing metadata for each
        linked library found, with keys:
            - name (str): Name of the library (e.g., 'lib-curl' for '-lcurl').
            - version (str): 'unknown' (default, as version is not extracted).
            - vendor (str): 'unknown' (default, vendor is not detected).
            - type (str): Always 'package' to indicate it’s a package-level dependency.
            - file (str): Path to the Makefile being parsed.
        """
        print(f"parsing Makefile {path}")
        packages = []
        try:
            with open(path ,encoding="utf-8",errors="ignore") as f:
                content = f.read()
                cleaned_content = "\n".join(line for line in content.splitlines() if not line.lstrip().startswith('#'))
                #it looks for wich ever is getting linked
                #Example: -lcurl => curl
                linked_lib = re.finditer(r'\s+-l([\w\-]+)',cleaned_content)
                for libs in linked_lib:
                    lib = libs.group(1)
                    if len(lib)> 0:
                        vendor = self.get_vendor(f'lib-{lib}')
                        packages.append({'name': f'lib-{lib}', 'version': 'unknown', 'vendor': vendor, 'type': 'package', 'file': path})
            return packages
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    def _parse_cmake_file(self,path):
        """
    Parses a CMake file to extract package dependencies declared using
    `pkg_check_modules` and `find_package` commands.

    Args:
        path (str): The file path to the CMake file.

    Returns:
        List[dict]: A list of dictionaries, each representing a detected package with:
                    - name (str): Package name
                    - version (str): Version or version specifier (if available)
                    - vendor (str): Vendor (defaulted to 'unknown')
                    - type (str): Always 'package'
                    - file (str): Path to the CMake file
        """
        print(f'Parsing cmake file {path}')
        packages = []
        try:
            with open(path,encoding='utf-8',errors="ignore") as f:
                content = f.read()
                #to remove comments
                cleaned_content = "\n".join(line for line in content.splitlines() if not line.lstrip().startswith('#'))
                #Example: PKG_CHECK_MODULES(OPENSSL, [libcrypto >= 1.1.0], [have_crypto_openssl=yes], [have_crypto_openssl=no])
                pattern = re.finditer(
                    r'pkg_check_modules\s*\(\s*\w+'
                    r'(.*?)'
                    r'\)',cleaned_content,re.IGNORECASE| re.DOTALL)

                for match in pattern:
                    module_spec = match.group(1)
                    #Example: pkg_check_modules(LibFido2 REQUIRED IMPORTED_TARGET libfido2>=1.3.0)
                    flags = ['REQUIRED', 'QUIET', 'IMPORTED_TARGET', 'GLOBAL', 'NO_CMAKE_PATH', 'NO_CMAKE_ENVIRONMENT_PATH']
                    tokens = re.split(r'[\s\n]+',module_spec.strip())
                    modules = [token for token in tokens if token not in flags]
                    for module in modules:
                        if not module:
                            continue
                        if module[0] == "'" or module[0] == '"':
                                module = module[1:]
                        if module[-1] == '"' or module[-1] == "'":
                                module = module[:-1]
                        match = re.search(r'[>=|<=|>|<]',module)
                        if match:
                            index=  match.start()
                            name = module[:index]
                            if name.startswith('${') and name.endswith('}'):
                                continue
                            vendor = self.get_vendor(name)
                            packages.append({'name': name , 'version': module[index:],'vendor':vendor,'type':'package','file':path})
                        else:
                            if module.startswith('${') and module.endswith('}'):
                                continue
                            vendor = self.get_vendor(module)
                            packages.append({'name': module , 'version': 'unknown','vendor':vendor,'type':'package','file':path})

                pattern = re.finditer(r'find_package\s*\((.*?)\)',cleaned_content,re.IGNORECASE|re.DOTALL)
                for matchs in pattern:
                    match = matchs.group(1)
                    parameters = re.split(r'[\s\n]+',match.strip())
                    version_match = None
                    if len(parameters) >= 1:
                        name = parameters[0]
                        if len(name) > 0:
                            if len(parameters) >= 2:
                                version_match = re.fullmatch(r'\d+(\.\d+)*',parameters[1])
                                if name[0] == "'" or name[0] == "'":
                                    name = name[1:]
                                if name[-1] == "'" or name[-1] == '"':
                                    name = name[:-1]
                            if version_match is not None:
                                    if name.startswith('${') and name.endswith('}'):
                                        continue
                                    vendor = self.get_vendor(name)
                                    packages.append({'name': name , 'version': parameters[1],'vendor':vendor,'type':'package','file':path})
                            else:
                                    if name.startswith('${') and name.endswith('}'):
                                        continue
                                    vendor = self.get_vendor(name)
                                    packages.append({'name': name , 'version': 'unknown','vendor':vendor,'type':'package','file':path})
            return packages
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    def _parse_configure_ac(self,path):
        """
    Extracts the value assigned to a specific variable from a file.

    Args:
        path (str): Path to the file to read from.
        variable (str): Variable name to search for.

    Returns:
        str or None: The value assigned to the variable, or None if not found.
        """
        print(f"parsing configure.ac file {path}")
        packages = []
        try:
            with open(path,encoding="utf-8",errors="ignore") as f:
                content = f.read()
                cleaned_content = "\n".join(line for line in content.splitlines() if not line.lstrip().startswith('#'))
                #Example:PKG_CHECK_MODULES(GTK4, gtk4 >= 4.0)
                pkg_check_matches = re.finditer(r'PKG_CHECK_MODULES\s*\((.*?)\s*\)',
                    cleaned_content, re.IGNORECASE|re.DOTALL)

                for match in pkg_check_matches:
                    var_name = match.group(1).strip()
                    modules = var_name.split(',')
                    if len(modules) >=2:
                        module = modules[1].strip()
                        #Example:PKG_CHECK_MODULES([CURL], [libcurl >= 7.19])
                        #Example:PKG_CHECK_MODULES([JWT], [libjwt >= 1.12])
                        if module.startswith('[') and module.endswith(']'):
                            module = module[1:-1]
                            packages.extend(self._list_from_string(require_string=
                                                                   module,type_string="package",path=path))
            return packages
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    def _parse_meson_file(self,path):
        """
    Parses a Meson build file to extract package dependencies.

    Args:
        path (str): Path to the 'meson.build' file.

    Returns:
        list[dict]: A list of dictionaries where each dictionary contains the following:
            - name (str): Package name
            - version (str): Package version (extracted or marked as 'unknown')
            - vendor (str): Vendor is set as 'unknown' (can be refined later)
            - type (str): Set to 'package'
            - file (str): Path to the parsed file
        """
        print(f"Parsing Meson build file: {path}")
        packages = []
        try:
            with open(path ,encoding="utf-8") as f:
                content = f.read()

                # Extract dependencies
                dependencies = re.finditer(
                    r"dependency\((.*?)\)",
                    content , re.IGNORECASE| re.DOTALL
                )
                for deps in dependencies:
                    dep = deps.group(1)
                    dep = " ".join(dep.split())
                    key_value_pairs = dep.split(",")
                    name = key_value_pairs[0].replace("'","")
                    if len(name) > 0:
                        version = "unknown"
                        for key_value in key_value_pairs:
                            if ':' in key_value:
                                key,value = key_value.split(":",1)
                                if key.strip().lower() == 'version':
                                    # if the version contains qoutes then it is version otherwise it is a variable
                                    if "'" in value:
                                        version = value.replace("'", "").strip()
                                        version = version.replace(" ","")
                                    else:
                                        version = self._extract_version_from_variables(value.strip() , path)
                                    # print(version)
                        vendor = self.get_vendor(name)
                        packages.append({
                            'name': name,
                            'version': version,
                            'vendor': vendor,
                            'type': 'package',
                            'file': path
                        })

            return packages
        except Exception as e:
            print(f"Exception {e} in parsing {path} :")
            return []

    def _extract_version_from_variables(self,variable , path):
        """
    Attempts to resolve the version value of a variable from a Meson build file.

    Args:
        variable (str): The variable name to search for.
        path (str): The path to the Meson build file.

    Returns:
        str: The resolved version string if found, otherwise 'unknown'.
        """
        try:
            with open(path,encoding="utf-8") as f:
                content = f.read()
                match = re.search(rf'\s*{re.escape(variable)}\s*=\s*(.*)',content)
                if match:
                    version = match.group(1)
                    if "'" in version:
                        version = version.replace("'","")
                        version = version.replace(" ","")
                        return version
                    else:
                        self._extract_version_from_variables(version,path)
        except Exception as e:
            print(f"Exception occured in extracting {e} version from variable path:{path}")
            return []

    def querry_ai(self,lib,search_result,api_url="http://localhost:11434" ):
        """
        Queries a locally running LLM (e.g., Qwen-14B via Ollama) to identify the vendor/organization
        associated with a given software package, based on the package name and relevant web search results.

        Args:
            lib (str): The name of the package/library.
            search_result (str): Web search result text (titles and URLs) to give the model context.
            api_url (str): Base URL of the local LLM API (default is Ollama on localhost).

        Returns:
            str: The vendor name identified by the model, cleaned and normalized.
                Returns "Unknown" if the model fails or gives no usable output.
        """
        model = "qwen:14b"

        url = f"{api_url}/api/generate"
        prompt =  f"""Given the package name "{lib}", identify the most likely vendor/organization that maintains this package.
        Guidelines:
        - For well-known libraries, return the organization name (e.g., "Google", "Microsoft", "Apache", "Mozilla")
        - For system libraries (lib-*),return OS vendor if known
        - If uncertain or unknown, return exactly: Unknown
        - Return **only** the vendor name, with no explanation or extra characters

        Here are some search results that may help:
        {search_result}
        Package name: {lib}
        Vendor:"""

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.9,
                "top_p": 0.95,
                "penalty": 0,
                "num_predict": 50,
                "stop": ["\n", "Package:", "Explanation:", "Guidelines:"]
            }
        }
        response  = requests.post(url, json=payload, timeout=60)
        try:
            if response.status_code == 200:
                result = response.json()
                model_response = result.get('response', '').strip()
                # Clean up the response - take first line and remove quotes
                model_response = model_response.split('\n')[0].strip()
                model_response = model_response.replace('"', '').replace("'", "")
                return model_response if model_response else "Unknown"
        except Exception:
            return "Unknown"
        return "Unknown"

    def search_package(self,pkg_name, max_results=3):
        """
    Performs a DDGS web search for a given package name to gather
    contextual information (titles + URLs) that may help the LLM identify its vendor.

    Args:
        pkg_name (str): The name of the package to search for.
        max_results (int): Maximum number of search results to retrieve (default is 3).

    Returns:
        str: A formatted string containing the top result titles and URLs,
             suitable for passing into the prompt of a language model.
    """
        with DDGS() as ddgs:
            # focused_query = (
            # f"{pkg_name} site:packages.debian.org "
            # f"OR site:rpmfind.net OR site:archlinux.org "
            # f"OR site:pkgs.alpinelinux.org OR site:packages.ubuntu.com"
            # )
            general_query = (
            f"{pkg_name} package"
            )
            # results_focus = ddgs.text(keywords=pkg_name, region='in-en', safesearch='Off', max_results=max_results , query=focused_query)
            results_general = ddgs.text(keywords=pkg_name, region='in-en', safesearch='Off', max_results=max_results , query=general_query)
            result = ""
            for r in results_general:
                title = r['title']
                href = r['href']
                result += f'title: {title}\n href: {href}\n'
            print("search result -------------------------------")
            print(result)
            return result

    def get_vendor(self,lib):
        """
    Determines the vendor or organization associated with a given package name
    by performing a DDGS search and querying a local LLM (e.g., Qwen-14B via Ollama).

    This function also cleans and normalizes the model's response to remove
    common noise patterns, such as:
        - Prefixes like "vendor: "
        - Quotation marks
        - Explanatory suffixes (e.g., "(Open Source)", "– Maintainer", ": Org")

    Args:
        lib (str): The name of the package or library to analyze.

    Returns:
        str: The cleaned vendor name (e.g., "Google", "Apache").
             Returns "Unknown" if the model fails to produce a meaningful result.
    """
        search_result = self.search_package(lib)
        # result =  self.querry_ai(lib,search_result)
        # #the result from the llm can be of the form
        # #vendor: name
        # #name
        # #"name"
        # #name (explanation)
        # #vendor: name (explanation)
        # result = re.sub(r'^vendor\s*:\s*', '', result.strip() , re.IGNORECASE)
        # result = result.strip('"').strip("'")
        # result = re.split(r'\s*\(|\s*[\-\–]\s*|\s*:\s*', result)[0]
        # return result
        # print("ai-vendor: ", options[self.i])
        # self.i=self.i+1
        # return options[self.i]
        return "unknown"
