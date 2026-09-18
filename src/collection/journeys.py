"""
Benign journeys —   data-driven (  )   app-agnostic.

 journey = list  steps.   step:
  {"do": "goto", "path": "/#/search"}            →   (GET )
  {"do": "fill", "selector": "#q", "value": "apple"}
  {"do": "click", "selector": "button[type=submit]"}

:  selectors      .
 goto steps         selectors.
"""

# Randomized fill-in values for {placeholder} path templates below (see
# _fill_path_params in benign_driver.py). WHY THIS EXISTS: with only ~5
# journeys per app and 10-25 actions per session, benign_driver.py used to
# pick the SAME journey many times per session; for search_products/
# view_product that meant the exact literal request (same fixed search term
# / same fixed product id) got repeated over and over - a real, massive
# source of byte-identical duplicates (confirmed: merge_jsonl.py dropped 64%
# of all raw records as exact dupes). Randomizing the term/id per visit
# means repeats of these two journeys still produce genuinely different
# requests instead of literal repeats.
SEARCH_TERMS = ["apple", "juice", "banana", "orange", "melon", "smoothie",
                "citrus", "fruit", "lemon", "mango", "berry", "grape",
                "carrot", "eggfruit", "cherry", "cola", "coffee", "tea",
                "honey", "raspberry", "strawberry", "watermelon",
                "pineapple", "kiwi", "peach", "plum", "papaya", "coconut",
                "vanilla", "lime", "sauce", "shirt", "sticker", "mug",
                "salt", "gift", "card", "green", "organic", "lemonade"]
PRODUCT_IDS = list(range(1, 31))  # Juice Shop's demo catalog (~40 products)

# Harmless values used to hit the SAME parameterized endpoints the attacks
# target, but benignly. This matters TWO ways:
#   1. Diversity: varied ids/names produce genuinely unique requests instead of
#      re-hitting one static paramless page (e.g. /index.php was captured 299x
#      as byte-identical dupes - see the path-frequency audit).
#   2. Methodology: the classifier MUST see benign traffic on the exact routes
#      the SQLi/XSS/path-traversal attacks use, otherwise it can cheat by
#      memorizing the route ("/vulnerabilities/sqli/ => attack") instead of
#      learning the payload. These journeys supply the benign counter-examples
#      on those routes.
BENIGN_NAMES = ["John", "Sara", "Ali", "Mona", "Omar", "Lina", "guest",
                "visitor", "Ahmed", "Nour", "test_user", "Yara",
                "Maya", "Kareem", "Hana", "Youssef", "Salma", "Tarek",
                "Dina", "Ramy", "Layla", "Adam", "Nadia", "Hassan",
                "Farida", "Khaled", "Rana", "Sami", "Aya", "Ziad",
                "Mariam", "Fady", "Reem", "Bassel", "Habiba", "Ihab",
                "user1", "user2", "admin2", "demo"]

JOURNEYS = {
    # ---------- Juice Shop (Angular SPA — hash routes + REST API) ----------
    "browse_home":     [{"do": "goto", "path": "/"}],
    "search_products": [
        {"do": "goto", "path": "/#/search"},
        {"do": "goto", "path": "/rest/products/search?q={term}"},
        {"do": "goto", "path": "/rest/products/search?q={term}"},
    ],
    "view_product":    [{"do": "goto", "path": "/api/Products/{id}"},
                        {"do": "goto", "path": "/api/Products/{id}"}],
    "api_products":    [{"do": "goto", "path": "/rest/products"}],
    "about_pages":     [{"do": "goto", "path": "/#/about"},
                        {"do": "goto", "path": "/#/contact"}],

    # ---------- WebGoat (Java) ----------
    "browse_lessons":  [{"do": "goto", "path": "/start.mvc"},
                        {"do": "goto", "path": "/service/lessonmenu.mvc"}],
    "view_profile":    [{"do": "goto", "path": "/service/lessonoverview.mvc"}],

    # ---------- DVWA (PHP) ----------
    "browse_menu":     [{"do": "goto", "path": "/index.php"},
                        {"do": "goto", "path": "/security.php"}],
    "view_instructions": [{"do": "goto", "path": "/instructions.php"},
                          {"do": "goto", "path": "/about.php"}],
    # DVWA parameterized BENIGN journeys - same endpoints the SQLi / XSS /
    # path-traversal (File Inclusion) attacks target, but with harmless,
    # randomized values (see BENIGN_NAMES / PRODUCT_IDS). Requires the low
    # security level + logged-in session the driver already sets up.
    "dvwa_sqli_benign":  [{"do": "goto", "path": "/vulnerabilities/sqli/?id={id}&Submit=Submit"}],
    "dvwa_xss_r_benign": [{"do": "goto", "path": "/vulnerabilities/xss_r/?name={name}"}],
    "dvwa_fi_benign":    [{"do": "goto", "path": "/vulnerabilities/fi/?page=include.php"},
                          {"do": "goto", "path": "/vulnerabilities/fi/?page=file{id}.php"}],
    "dvwa_brute_benign": [{"do": "goto", "path": "/vulnerabilities/brute/?username={name}&password=pass{id}&Login=Login"}],

    # ----------  ----------
    "static_pages":    [{"do": "goto", "path": "/robots.txt"},
                        {"do": "goto", "path": "/favicon.ico"}],
    "login":           [{"do": "login"}],   #   handler    driver

    # ---------- Mutillidae II (PHP) - added 2026-09-18 ----------
    # Page names read directly from the site's own menu HTML (already
    # confirmed, not guessed): homepage + two harmless "Others" pages.
    "mutillidae_home":      [{"do": "goto", "path": "/index.php"}],
    "mutillidae_blog":      [{"do": "goto", "path": "/index.php?page=add-to-your-blog.php"},
                             {"do": "goto", "path": "/index.php?page=view-someones-blog.php"}],
    "mutillidae_text_view": [{"do": "goto", "path": "/index.php?page=text-file-viewer.php"},
                             {"do": "goto", "path": "/index.php?page=show-log.php"}],
}
