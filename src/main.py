from urllib.parse import urljoin

import requests
import time
import re
import json
import os
import subprocess
import configparser
import uuid
import socket
from bs4 import BeautifulSoup

import time
from python_anticaptcha import AnticaptchaClient, NoCaptchaTaskProxylessTask

from apify import Actor
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import TimeoutException

# To run this Actor locally, you need to have the Selenium Chromedriver installed.
# https://www.selenium.dev/documentation/webdriver/getting_started/install_drivers/
# When running on the Apify platform, it is already included in the Actor's Docker image.

# Parameters

LOOP_MAX = 50
SCROLL_INCREMENT = 600  # This value might need adjusting depending on the website

STORAGE_PATH = "storage"
PATHS = {
    'storage': STORAGE_PATH,
    'captures': os.path.join(STORAGE_PATH, "captures"),
    'mitmdump': os.path.join(STORAGE_PATH, "mitmdump"),
    'stdout_log_file' : '',
    'stderr_log_file' : '',
    'captured_file': '',
    'error_file': ''
}

async def main():
    async with Actor:
        
        
        actor_input = await Actor.get_input() or {}
        urls = actor_input.get('urls', 'https://www.foodpanda.com.kh/en/restaurant/g4oa/')

        if not urls:
            Actor.log.info('No  URLs specified in actor input, exiting...')
            await Actor.exit()
        
        # Enqueue the starting URLs in the default request queue
        default_queue = await Actor.open_request_queue()
        for urlo in urls:
            url = urlo.get('url')
            Actor.log.info(f'Enqueuing {url} ...')
            await default_queue.add_request({ 'url': url})
        
        while request := await default_queue.fetch_next_request():
            url = request['url']
            Actor.log.info(f'Processing {url} ...')

            unique_id = str(uuid.uuid4())
            Actor.log.info("Using unique id: "+str(unique_id))

            paths = update_paths(unique_id)
            # Start the MITM proxy
            proxy_port = find_open_port()
            Actor.log.info("Using proxy port: "+str(proxy_port))
            mitm_process = start_mitmproxy(unique_id, proxy_port)

            # Load website
            driver = get_driver(proxy_port)
            await process_website(driver, url) 
                    
            driver.quit()
            stop_mitmproxy(mitm_process)
            await process_capture(unique_id)
            clean_files()

def ensure_directory_exists(directory: str):
    if directory and not os.path.exists(directory):
        os.makedirs(directory)

def update_paths(unique_id: str):

    PATHS['stdout_log_file']    = os.path.join(PATHS['mitmdump'], f'mitmdump_stdout_{unique_id}.log')
    PATHS['stderr_log_file']    = os.path.join(PATHS['mitmdump'], f'mitmdump_stderr_{unique_id}.log')
    PATHS['captured_file']      = os.path.join(PATHS['captures'], f"captured_requests_{unique_id}.txt")
    PATHS['error_file']         = os.path.join(PATHS['captures'], f"errors_{unique_id}.txt")

    # List of directory paths to ensure exist
    directories_to_ensure = [
        PATHS['storage'],
        PATHS['captures'],
        PATHS['mitmdump'],
    ]

    # Ensure directories exist
    for directory in directories_to_ensure:
        ensure_directory_exists(directory)

    return PATHS

async def process_website(driver, url):     

    driver.get(url)
    time.sleep(3)

    check_captcha(driver)

    title = driver.title
    try:
        # wait to load the page
        element_present = EC.presence_of_element_located((By.ID, 'vendor-details-root'))
        WebDriverWait(driver, 10).until(element_present)
        time.sleep(2)
    except TimeoutException:
        Actor.log.error("The expected element did not appear in the specified time! Closing the driver...")
        return       

    scroll_to_bottom(driver)

    # First get the actual web elements
    item_elements = driver.find_elements(By.CSS_SELECTOR, 'li[data-testid="menu-product"]')

    # Then extract their HTML content into a list
    item_wrappers = [item.get_attribute('outerHTML') for item in item_elements]

    # Get the count of items and log them
    item_count = len(item_wrappers)
    Actor.log.info(f'Webscraper located {item_count} items.')

    # Loop through and process each div (which is now the HTML content of each item)
    for item_html in item_wrappers:
        item_data = extract_item_data(item_html)
        if item_data is not None:
            item_data['url'] = url
            item_data['restaurant'] = title
            await Actor.push_data(item_data)

def extract_item_data(item_html):
    data = {}
    soup = BeautifulSoup(item_html, 'html.parser')

    # Extract dish name
    dish_name_tag = soup.find('span', {'data-testid': 'menu-product-name'})
    data['name'] = dish_name_tag.text if dish_name_tag else None

    # Extract dish description
    dish_description_tag = soup.find('p', {'data-testid': 'menu-product-description'})
    data['description'] = dish_description_tag.text.strip() if dish_description_tag else None

    # Extract dish price
    dish_price_tag = soup.find('p', {'data-testid': 'menu-product-price'})
    data['price'] = dish_price_tag.text.strip() if dish_price_tag else None

    # Extract dish image URL
    dish_image_div = soup.find('div', {'data-testid': 'menu-product-image'})
    if dish_image_div and dish_image_div.get('style'):
        data['image_url'] = dish_image_div.get('style').split('"')[1]
    else:
        data['image_url'] = None

    return data


def scroll_to_bottom(driver):
    loop_count = 0
    loop_max = LOOP_MAX
    while True:
        current_position = driver.execute_script("return window.pageYOffset;")
        driver.execute_script(f"window.scrollTo(0, {current_position + SCROLL_INCREMENT});")
        time.sleep(1)
        new_height = driver.execute_script("return document.body.scrollHeight")
        if current_position + SCROLL_INCREMENT >= new_height:
            break
        if loop_count >= loop_max:
            break
        loop_count = loop_count + 1

def check_captcha(driver):
    # Check fo catpcha
    captcha = driver.find_elements(By.CSS_SELECTOR, '.px-captcha-container')
    if captcha:
        msg = "Captcha detected! Exiting..."
        Actor.log.warning(msg)

        sitekey = get_captcha_sitekey(driver)
        Actor.log.info("Sitekey detected: %s", sitekey)

        api_key = get_anti_captcha_api_key()
        client = AnticaptchaClient(api_key)
        url = driver.current_url

        invisible_captcha = True
        token = get_captcha_token(client, url, sitekey, invisible_captcha)

        form_captch_solution_submit(driver, token)
   
        successmsg = driver.find_element_by_class_name("recaptcha-success").text
        Actor.log.info("Captcha solved: %s", successmsg)


def form_captch_solution_submit(driver, token):
    driver.execute_script(
        "document.getElementById('g-recaptcha-response').innerHTML='{}';".format(token)
    )
    driver.execute_script("onSuccess('{}')".format(token))
    time.sleep(2)

def get_captcha_token(client, url, site_key, invisible):
    task = NoCaptchaTaskProxylessTask(
        website_url=url, website_key=site_key, is_invisible=invisible
    )
    job = client.createTask(task)
    job.join(maximum_time=60 * 15)
    return job.get_solution_response()

def get_captcha_sitekey(driver):
    return driver.find_element_by_class_name("g-recaptcha").get_attribute(
        "data-sitekey"
    )

def get_driver(proxy_port = 8080):
    # Launch a new Selenium Chrome WebDriver
    Actor.log.info('Launching Chrome WebDriver...')
    chrome_options = ChromeOptions()
    #    if Actor.config.headless:
    #        chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')

    PROXY = "localhost:" + str(proxy_port)
    chrome_options.add_argument(f"--proxy-server={PROXY}")
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--ignore-ssl-errors')
    driver = webdriver.Chrome(options=chrome_options)

    return driver

async def process_capture(unique_id):
    captured_file_path = PATHS['captured_file']
    
    # Ensure that the file is read using 'utf-8' encoding
    with open(captured_file_path, "r", encoding='utf-8') as file:
        lines = file.readlines()
    
    dataset = await Actor.open_dataset(name='captured-items')

    # Loop through the lines
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if "Response Body:" in line:
            i += 1  # Move to the next line where the actual response body is
            if i < len(lines):  # Ensure we don't go out of bounds
                response_body = lines[i].strip()

                # Check if the response body is empty
                if not response_body:
                    Actor.log.warning(f"Empty Response Body found on line {i + 1}.")
                # Check if the response body is a valid JSON
                elif is_valid_json(response_body):
                    # Actor.log.info("Processing file JSON catpure...")                    
                    data = json.loads(response_body)
                    await process_items(data, dataset)                    
                else:
                    Actor.log.error(f"Invalid JSON found on line {i + 1}.")
        i += 1

async def process_items(data, dataset):
    if not isinstance(data, dict):
        Actor.log.error("Expected data to be a dictionary but received a %s", type(data))
        return
    
    try:
        # Check the status_code in the JSON data
        status_code = data.get('status_code')
        if status_code != 200:
            Actor.log.error("Error in capture with status code: %s", status_code)
            Actor.log.debug(data)
            return

        await dataset.push_data(data.get('data'))
    except Exception as e:
        Actor.log.error("Error while processing items: %s", str(e))

def find_open_port(start_port=8080):
    port = start_port
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            socket_result = s.connect_ex(('localhost', port))
            if socket_result == 0:  # port is already in use
                port += 1
            else:
                return port

def start_mitmproxy(unique_id, port = 8080):
    # Ensure data folder exists or create it
    data_folder = PATHS['storage']
    if not os.path.exists(data_folder):
        os.makedirs(data_folder)   

    # Set path to the mitmdump script inside the data folder
    dump_script_path = os.path.join("src", "save_requests.py")

    # Define paths for stdout and stderr logs
    stdout_log_path = PATHS['stdout_log_file']
    stderr_log_path = PATHS['stderr_log_file']

    # Start mitmdump with the specified port
    with open(stdout_log_path, 'w') as stdout_file, open(stderr_log_path, 'w') as stderr_file:
        cmd = f'mitmdump --quiet -p {port} -s {dump_script_path} {unique_id} > {stdout_log_path} 2> {stderr_log_path}'
        process = subprocess.Popen(cmd, shell=True)

    time.sleep(3)

    # Check the stderr log for errors
    with open(stderr_log_path, 'r') as stderr_file:
        error_output = stderr_file.read()
        if "Address already in use" in error_output:
            raise Exception("Another process is already using the required port. Make sure mitmproxy isn't already running.")
        elif "Error" in error_output:
            raise Exception(f"Error starting mitmproxy: {error_output}")

    return process

def stop_mitmproxy(process):
    try:
        # Send a SIGTERM signal to the process
        process.terminate()
        # Wait for up to 5 seconds for the process to terminate
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        # If the process doesn't terminate within the timeout, forcibly kill it
        process.kill()
    Actor.log.info("Mitmproxy stopped.")

def is_valid_json(s):
    try:
        json.loads(s)
        return True
    except ValueError:
        return False
    
def clean_files():
    Actor.log.info("Cleaning up files...")
    delete_files(PATHS['stdout_log_file'], PATHS['stderr_log_file'], PATHS['captured_file'], PATHS['error_file'])

def delete_files(*file_paths):
    """Delete files specified by their paths."""
    for path in file_paths:
        try:
            os.remove(path)
            #Actor.log.info(f"Successfully deleted {path}")
        except FileNotFoundError:
            Actor.log.warning(f"{path} not found.")
        except Exception as e:
            Actor.log.error(f"Error deleting {path}: {e}")

def get_maps_api_key():
    # Try to get the API key from the environment variable first
    api_key = os.getenv('GOOGLE_MAPS_API_KEY')

    if api_key:
        Actor.log.info("API key fetched from environment variable.")
        return api_key

    # If not found, then fetch it from the config.ini file
    config = configparser.ConfigParser()
    config.read('config.ini')

    # Check if the config file is found and read
    if not config.sections():
        Actor.log.error("Error: config.ini not found or empty!")
        return None

    # Check if the "GoogleMaps" section exists in the config
    if 'GoogleMaps' not in config.sections():
        Actor.log.error("Error: 'GoogleMaps' section not found in config.ini!")
        return None

    try:
        api_key = config['GoogleMaps']['GOOGLE_MAPS_API_KEY']
        Actor.log.info("API key fetched from config.ini.")
        return api_key
    except KeyError:
        Actor.log.error("Error: Couldn't find the 'GOOGLE_MAPS_API_KEY' in 'GoogleMaps' section of config.ini!")
        return None
    

def get_anti_captcha_api_key():
    # Try to get the API key from the environment variable first
    api_key = os.getenv('ANTI_CAPTCHA_API_KEY')

    if api_key:
        Actor.log.info("Anti_Captcha_key fetched from environment variable.")
        return api_key

    # If not found, then fetch it from the config.ini file
    config = configparser.ConfigParser()
    config.read('config.ini')

    # Check if the config file is found and read
    if not config.sections():
        Actor.log.error("Error: config.ini not found or empty!")
        return None

    # Check if the "AntiCaptcha" section exists in the config
    if 'AntiCaptcha' not in config.sections():
        Actor.log.error("Error: 'Anti_Captcha_key' section not found in config.ini!")
        return None

    try:
        api_key = config['AntiCaptcha']['ANTI_CAPTCHA_API_KEY']
        Actor.log.info("API key fetched from config.ini.")
        return api_key
    except KeyError:
        Actor.log.error("Error: Couldn't find the 'ANTI_CAPTCHA_API_KEY' in config.ini!")
        return None