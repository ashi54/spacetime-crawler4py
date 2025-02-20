import re
import hashlib
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urldefrag, urljoin
import atexit
from collections import defaultdict


ALLOWED_DOMAINS = [
    r'.*\.ics\.uci\.edu',
    r'.*\.cs\.uci\.edu',
    r'.*\.informatics\.uci\.edu',
    r'.*\.stat\.uci\.edu'
]

visited_links = set()
word_frequency_map = defaultdict(int)
subdomain_counts = defaultdict(int)
page_with_max_words = {"url": "", "word_count": 0}
checksum_set = set()

logging.basicConfig(filename="crawler_log.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


stopwords = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "aren't",
    "as", "at", "be", "because", "been", "before", "being", "below", "between", "both", "but", "by",
    "can", "cannot", "could", "couldn't", "did", "didn't", "do", "does", "doesn't", "doing", "don't",
    "down", "during", "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't", "have",
    "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here", "here's", "hers", "herself",
    "him", "himself", "his", "how", "how's", "i", "i'd", "i'll", "i'm", "i've", "if", "in", "into",
    "is", "isn't", "it", "it's", "its", "itself", "let's", "me", "more", "most", "mustn't", "my",
    "myself", "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our",
    "ours", "ourselves", "out", "over", "own", "same", "shan't", "she", "she'd", "she'll", "she's",
    "should", "shouldn't", "so", "some", "such", "than", "that", "that's", "the", "their", "theirs",
    "them", "themselves", "then", "there", "there's", "these", "they", "they'd", "they'll", "they're",
    "they've", "this", "those", "through", "to", "too", "under", "until", "up", "very", "was", "wasn't",
    "we", "we'd", "we'll", "we're", "we've", "were", "weren't", "what", "what's", "when", "when's",
    "where", "where's", "which", "while", "who", "who's", "whom", "why", "why's", "with", "won't",
    "would", "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours", "yourself",
    "yourselves"
}

""" EXTRACTING & PROCESSING PAGE CONTENT """
def scraper(url, resp):
    if resp.status >= 400 or resp.raw_response is None:
        return []

    if detect_repetitive_patterns(url):
        return []


    # Parse Page Content
    soup = BeautifulSoup(resp.raw_response.content, "html.parser")
    text = soup.get_text()
    checksum = compute_checksum(text)
    tokens = tokenize(text)

    if is_low_quality(resp, text, tokens):
        return []

    # Detect Duplicate Pages
    if checksum in checksum_set:
        return []
    checksum_set.add(checksum)

    # Update Analysis Stats
    record_page_visit(url)
    track_longest_page(url, tokens)
    count_word_frequencies(tokens)
    track_subdomains(url)

    # Extract & Validate Links
    links = extract_hyperlinks(url, resp)
    return [link for link in links if is_valid(link) and link not in visited_links]


def extract_hyperlinks(url, resp):
    if resp.status != 200 or resp.raw_response is None:
        return []

    soup = BeautifulSoup(resp.raw_response.content, "html.parser")
    hyperlinks = set()

    for a_tag in soup.find_all("a", href=True):
        absolute_url = urljoin(url, a_tag["href"])
        clean_url, _ = urldefrag(absolute_url)
        hyperlinks.add(clean_url)

    return list(hyperlinks)


""" ANALYSIS & FINAL REPORT METHODS """
def record_page_visit(url):
    visited_links.add(url)


def track_longest_page(url, tokens):
    word_count = len(tokens)
    if word_count > page_with_max_words["word_count"]:
        page_with_max_words["word_count"] = word_count
        page_with_max_words["url"] = url


def count_word_frequencies(tokens):
    for token in tokens:
        if token not in stopwords:
            word_frequency_map[token] += 1


def track_subdomains(url):
    parsed_url = urlparse(url)
    if parsed_url.netloc.endswith("ics.uci.edu"):
        subdomain_counts[parsed_url.netloc] += 1


def generate_report():
    report_lines = []
    
    report_lines.append("\n=== Final Report ===")
    report_lines.append(f"Total Unique Pages Found: {len(visited_links)}")
    report_lines.append(f"Longest Page: {page_with_max_words['url']} ({page_with_max_words['word_count']} words)")
    
    sorted_words = sorted(word_frequency_map, key=word_frequency_map.get, reverse=True)[:50]
    report_lines.append("\nTop 50 Most Common Words (excluding stopwords):")
    for word in sorted_words:
        report_lines.append(f"{word}: {word_frequency_map[word]}")

    sorted_subdomains = sorted(subdomain_counts.items(), key=lambda x: x[0])
    report_lines.append("\nSubdomains Found in ics.uci.edu:")
    for subdomain, count in sorted_subdomains:
        report_lines.append(f"{subdomain}, {count}")

    # Print to console and write to file
    final_report = "\n".join(report_lines)
    print(final_report)
    
    with open("report.txt", "w") as f:
        f.write(final_report)



""" VALIDITY TESTING METHODS """
def is_valid(url):
    """
    Determines whether a URL should be crawled or not.
    Returns True if the URL is valid, otherwise False.
    """
    try:
        parsed = urlparse(url)

        # Ensure the URL uses an acceptable scheme
        if parsed.scheme not in {"http", "https"}:
            return False

        # Regex to exclude unwanted file types
        invalid_extensions = (
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            r"|png|tiff?|mid|mp2|mp3|mp4"
            r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            r"|epub|dll|cnf|tgz|sha1"
            r"|thmx|mso|arff|rtf|jar|csv"
            r"|rm|smil|wmv|swf|wma|zip|rar|gz|ics)$"
        )

        if re.match(invalid_extensions, parsed.path.lower()):
            return False

        return True

    except Exception as e:
        logging.error(f"URL Validation Error: {url}, {e}")
        return False


def compute_checksum(text):
    return hashlib.md5(text.encode()).hexdigest()



def tokenize(text):
    """
    Extracts words from the given text.
    Filters out words shorter than two characters.
    """
    return re.findall(r'\b[a-zA-Z]{2,}\b', text.lower())


def detect_repetitive_patterns(url):
    """
    Identifies and prevents crawling of repetitive calendar-like URLs.
    Returns True if the URL contains date-based patterns that have been seen before.
    """
    date_pattern = re.compile(r'(\b\d{4}-\d{2}-\d{2}\b)|(\b\d{4}-\d{2}\b)')
    match = date_pattern.search(url)
    if match:
        base_url = url.replace(match.group(0), "DATE")
        if base_url in visited_links:
            logging.info(f"Detected Calendar Loop: {url}")
            return True
        visited_links.add(base_url)
    return False


def is_low_quality(resp, text, tokens):
    """
    Determines whether a page has low information value.
    Filters out pages that are too large or contain too little unique content.
    """
    threshold_size = 1 * 1024 * 1024  # 1MB
    unique_ratio = len(set(tokens)) / len(tokens) if len(tokens) > 0 else 0

    if len(resp.raw_response.content) > threshold_size:
        return True
    if len(tokens) < 50 or unique_ratio < 0.1:
        return True

    return False


""" EXIT HANDLER """
def exit_handler():
    generate_report()


atexit.register(exit_handler)