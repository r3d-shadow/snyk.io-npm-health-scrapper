## Generate SBOM => cyclonedx-npm  --ignore-npm-errors --output-format  json --output-file sbom.json
import json
import requests
from bs4 import BeautifulSoup
import time
from weasyprint import HTML, CSS

SNYK_NPM_HEACTH_CHECK_URL = "https://snyk.io/advisor/npm-package/"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
}

HEALTH_SCORE_THRESHOLD = 0.7
GIT_STARS_THRESHOLD = 2000
LAST_RELEASE_THRESHOLD = 1 # years

# def generate_markdown_table(data):
#     table = "| Health Score  | Security  | Popularity  | Maintenance  | Community  | Latest Version  | GitHub Stars  | Forks  | Contributors  | Open Issues  | Open PR  | Last Release | Last Commit |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
#     for package_info in data:
#         package = data[package_info]
#         table += f'| {package["Health Score"]}  | {package["security"]}  |{package["popularity"]}  |{package["maintenance"]}  |{package["community"]}  |{package["Latest Version"]}  |{package["GitHub Stars"]}  |{package["Forks"]}  |{package["Contributors"]}  |{package["Open Issues"]}  |{package["Open PR"]}  |{package["Last Release"]}  |{package["Last Commit"]}  |\n'
#     print(table)

def convert_to_numeric_with_suffix(value):
    if 'K' in value:
        return int(float(value[:-1]) * 1000)
    elif 'M' in value:
        return int(float(value[:-1]) * 1000000)
    else:
        return int(value)

def generate_html_table(data):
    table = "<table>\n<tr><th>Package</th><th>Current Version</th><th>Health Score</th><th>Security</th><th>Popularity</th><th>Maintenance</th><th>Community</th><th>Latest Version</th><th>GitHub Stars</th><th>Forks</th><th>Contributors</th><th>Open Issues</th><th>Open PR</th><th>Last Release</th><th>Last Commit</th></tr>\n"

    for package_info in data:
        package = data[package_info]
        try:
            security_style = ""
            if(package["security"] != "No known security issues"):
                security_style = 'style="color: red;"'
            maintenance_style = ""
            if(package["maintenance"] == "Inactive"):
                maintenance_style = 'style="color: red;"'
            health_score_style = ""
            if(eval(package["Health Score"]) < HEALTH_SCORE_THRESHOLD):
                health_score_style = 'style="color: red;"'
            git_stars_style = ""
            if(convert_to_numeric_with_suffix(package["GitHub Stars"]) < GIT_STARS_THRESHOLD):
                git_stars_style = 'style="color: red;"'
            last_release_style = ""
            if "years ago" in package["Last Release"] and int(package["Last Release"].split()[0]) >= LAST_RELEASE_THRESHOLD:
                last_release_style = 'style="color: red;"'

            table += f'<tr><td>{package["component"]}</td><td>{package["Current Version"]}</td><td {health_score_style}>{package["Health Score"]}</td><td {security_style} >{package["security"]}</td><td>{package["popularity"]}</td><td {maintenance_style}>{package["maintenance"]}</td><td>{package["community"]}</td><td>{package["Latest Version"]}</td><td {git_stars_style}>{package["GitHub Stars"]}</td><td>{package["Forks"]}</td><td>{package["Contributors"]}</td><td>{package["Open Issues"]}</td><td>{package["Open PR"]}</td><td {last_release_style}>{package["Last Release"]}</td><td>{package["Last Commit"]}</td></tr>\n'
        except Exception as e:
            print(f"An error occurred: {e}")
            table += f'<tr><td>{package["component"]}</td><td>{package["Current Version"]}</td><td>Something Went Wrong</td></tr>\n'
    table += "</table>"
    return table

def parse_snyk_health_html(html_content, package_info):
    try:
        soup = BeautifulSoup(html_content, 'html5lib') 
        ## ------------------ Health: START ------------------ 
        health_score = soup.find('div', attrs = {'class':'package-extra'}).find('div', attrs = {'class':'health'}).find('div').find('span')
        package_info['Health Score'] = health_score.text.strip()
        health_score_ul = soup.find('div', attrs = {'class':'package-extra'}).find('div', attrs = {'class':'health'}).find('ul')
        health_score_ul_li_elements = health_score_ul.find_all('li')
        for element in health_score_ul_li_elements:
            health_key = element.find('span')
            health_value = element.find('a').find('span')
            package_info[health_key.text.strip()] = health_value.text.strip()
        ## ------------------ Health: END ------------------ 

        ## ------------------ Security: START ------------------ 
        security = soup.find('div', attrs = {'id':'security'})
        latest_version = security.find('td')
        package_info['Latest Version'] = latest_version.text.strip()
        ## ------------------ Security: END ------------------ 

        ## ------------------ popularity: START ------------------ 
        popularity = soup.find('div', attrs = {'id':'popularity'})
        popularity_card_body_items = popularity.find('div', attrs = {'class':'card-body'}).find_all('div', attrs = {'class':'stats-item'}) 
        for element in popularity_card_body_items:
            dt_elements = element.find('dt')
            dd_elements = element.find('dd')
            package_info[dt_elements.text.strip()] = dd_elements.text.strip()
        ## ------------------ popularity: END ------------------ 

        # ------------------ maintenance: START ------------------ 
        maintenance = soup.find('div', attrs = {'id':'maintenance'})
        maintenance_card_body_items = maintenance.find('div', attrs = {'class':'card-body'}).find_all('div', attrs = {'class':'stats-item'}) 
        for element in maintenance_card_body_items:
            dt_elements = element.find('dt')
            dd_elements = element.find('dd')
            package_info[dt_elements.text.strip()] = dd_elements.text.strip()
        ## ------------------ maintenance: END ------------------ 
    except Exception as e:
        print(f"An error occurred: {e}")
        package_info['Health Score'] = '404: Something Went Wrong'
    return package_info

def scrape(package_data, package_key_name, output_file_name):
    with open(output_file_name) as f:
        result_data = json.load(f)
    project_info = result_data
    components = package_data[package_key_name]
    for index, (package_name, package_version) in enumerate(components.items()):
        print(f"Index: {index}")
        if package_name in result_data:
            print(f"------- {package_name}: PASS --------------")
            pass
        else:
            print(f"------- {package_name}: START --------------")
            package_info = {}
            package_info["Current Version"] = package_version
            snyk_npm_heacth_check_url_final = SNYK_NPM_HEACTH_CHECK_URL + package_name
            response = requests.get(snyk_npm_heacth_check_url_final, headers=HEADERS)
            if(response.status_code == 200 or response.status_code == 404):
                package_info['component'] = package_name
                package_info = parse_snyk_health_html(response.text, package_info)
                project_info[package_name] = package_info
                with open(output_file_name, 'w') as json_file:
                    json.dump(project_info, json_file, indent=2)
                print(f"------- {package_name}: END --------------")
                time.sleep(5)
            else:
                # Wait for 5 minutes (300 seconds)
                time.sleep(300)
    return project_info

with open('package.json') as f:
    package_data = json.load(f)

project_info = scrape(package_data, 'dependencies', 'dependencies.json')
dependencies_table_result = generate_html_table(project_info)

dev_project_info = scrape(package_data, 'devDependencies', 'dev-dependencies.json')
dev_dependencies_table_result = generate_html_table(dev_project_info)

html_content = f'''\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
        <style>
        table {{
            width: 80%;
            margin: 20px auto;
            background-color: #fff;
            border-collapse: collapse;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }}

        th, td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}

        th {{
            background-color: #3498db;
            color: #fff;
        }}
    </style>
</head>
<body>
    <div>
        <h2>Dependencies</h2>
        {dependencies_table_result}
    </div>
    <div>
        <h2>Dev Dependencies</h2>
        {dev_dependencies_table_result}
    </div>
</body>
</html>
'''
css = CSS(string=''' @page {size: 455mm 445.5mm;} ''')
HTML(string=html_content).write_pdf('result.pdf', stylesheets=[css])