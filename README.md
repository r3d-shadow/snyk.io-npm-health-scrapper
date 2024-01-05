# snyk.io-npm-health-scraper

## Overview

This project is a web scraper for fetching health metrics of npm packages from snyk.io. It extracts data such as Health Score, Security, Popularity, Maintenance, Community, and more.

## Usage

Follow the steps below to run the scraper:

1. **Replace `package.json` File:**
   Replace the `package.json` file with the one you want to analyze.

2. **Install Dependencies:**
   Run the following command to install the required Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Scraper:**
   Execute the Python script

   ```bash
   python index.py
   ```

The script will fetch and display the health metrics for the specified npm packages.