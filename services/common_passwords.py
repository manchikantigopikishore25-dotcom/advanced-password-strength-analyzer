"""
Local offline dataset of common compromised passwords, keyboard patterns,
and dictionary word roots for fast privacy-preserving detection.
No external network calls or remote API queries are performed.
"""

# Common passwords blocklist compiled from public breach statistics (RockYou/NIST/SecLists)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "12345", "1234", "111111",
    "1234567", "qwerty", "123123", "password1", "password123", "abc123",
    "admin", "welcome", "welcome1", "login", "guest", "root", "master",
    "secret", "pass1234", "default", "changeme", "letmein", "football",
    "iloveyou", "princess", "sunshine", "monkey", "dragon", "shadow",
    "superman", "michael", "jessica", "charlie", "hunter2", "trustno1",
    "starwars", "ninja", "mustang", "access", "computer", "internet",
    "freedom", "testing", "passcode", "baseball", "bailey", "orange",
    "purple", "cookie", "summer", "winter", "spring", "autumn",
    "november", "december", "january", "happy", "yellow", "coffee",
    "matrix", "chelsea", "arsenal", "liverpool", "barcelona", "realmadrid",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "000000", "666666", "777777",
    "888888", "999999", "121212", "112233", "654321", "54321", "admin123",
    "administrator", "server", "system", "service", "database", "oracle",
    "cisco", "passw0rd", "p@ssword", "p@ssw0rd", "p@55w0rd", "p@ss",
    "qwerty123", "welcome2020", "welcome2021", "welcome2022", "welcome2023",
    "welcome2024", "welcome2025", "welcome2026", "password2024", "password2025",
    "password2026", "temp1234", "temppass", "newpassword", "reset123"
}

# Common English word stems and dictionary words
DICTIONARY_WORDS = {
    "about", "access", "account", "action", "active", "admin", "almost", "always",
    "animal", "answer", "apple", "attack", "august", "autumn", "banana", "bank",
    "baseball", "beauty", "become", "before", "behind", "better", "beyond", "black",
    "blue", "board", "bottle", "branch", "bread", "bridge", "bright", "brother",
    "brown", "budget", "build", "button", "camera", "cancel", "candle", "canvas",
    "capital", "captain", "castle", "center", "chance", "change", "charge", "cheese",
    "cherry", "chicken", "church", "circle", "client", "cloud", "coffee", "college",
    "common", "company", "computer", "control", "cookie", "corner", "cotton", "country",
    "course", "cousin", "cover", "credit", "crypto", "custom", "danger", "database",
    "dealer", "decide", "degree", "delete", "device", "diamond", "dinner", "direct",
    "doctor", "dollar", "domain", "double", "dragon", "drawer", "dream", "driver",
    "eagle", "early", "earth", "easter", "editor", "effort", "engine", "enough",
    "enter", "escape", "estate", "event", "every", "expert", "factor", "falcon",
    "family", "famous", "farmer", "father", "female", "filter", "finger", "finish",
    "flight", "flower", "flying", "follow", "forest", "forget", "format", "fortune",
    "forward", "freeze", "friend", "future", "galaxy", "garden", "garlic", "gather",
    "gentle", "global", "golden", "guitar", "hammer", "handle", "happen", "harbor",
    "hazard", "health", "heaven", "helmet", "hidden", "history", "hockey", "holiday",
    "honest", "horizon", "horror", "horse", "hunter", "impact", "income", "infant",
    "inform", "inject", "inside", "island", "jacket", "jaguar", "january", "jersey",
    "jockey", "jungle", "junior", "justice", "keeper", "kernel", "kidney", "kitchen",
    "knight", "ladder", "laptop", "launch", "lawyer", "leader", "legacy", "lemon",
    "length", "lesson", "letter", "linear", "lion", "liquid", "listen", "little",
    "lizard", "locate", "lock", "london", "lucky", "lumber", "luxury", "machine",
    "magic", "magnet", "manage", "manual", "marble", "margin", "marine", "market",
    "master", "matrix", "matter", "meadow", "medium", "member", "memory", "mental",
    "method", "middle", "miller", "minute", "mirror", "mobile", "modern", "module",
    "monkey", "monk", "month", "morning", "mother", "motion", "mountain", "museum",
    "music", "mutual", "myself", "narrow", "nation", "native", "nature", "needle",
    "network", "neuron", "neutral", "newton", "nickel", "ninja", "nobody", "normal",
    "notice", "novel", "number", "object", "obtain", "office", "online", "orange",
    "orbit", "order", "origin", "output", "oxygen", "packet", "palace", "panther",
    "parent", "parrot", "partner", "passage", "patent", "patrol", "payment", "peanut",
    "pencil", "people", "pepper", "perfect", "period", "person", "phantom", "philosophy",
    "phone", "photo", "phrase", "physics", "pigeon", "pillow", "pilot", "pirate",
    "planet", "plastic", "platform", "player", "plenty", "pocket", "poetry", "police",
    "policy", "polite", "portal", "potato", "powder", "praise", "prayer", "prefer",
    "prince", "princess", "prison", "private", "prize", "problem", "process", "produce",
    "profit", "program", "project", "promise", "protect", "public", "pudding", "puppy",
    "purple", "purpose", "puzzle", "python", "quantum", "quarter", "queen", "query",
    "rabbit", "radar", "radiant", "radius", "railway", "rainbow", "random", "ranger",
    "record", "remote", "repair", "repeat", "report", "rescue", "resort", "return",
    "reward", "rhythm", "ribbon", "rich", "river", "robot", "rocket", "roller",
    "rooster", "rotate", "router", "rubber", "runner", "safari", "sailor", "salary",
    "salmon", "sample", "sand", "saturn", "scale", "scanner", "scheme", "school",
    "science", "screen", "script", "search", "season", "second", "secret", "sector",
    "secure", "sensor", "series", "server", "service", "shadow", "shield", "signal",
    "silver", "simple", "sister", "slight", "smart", "smile", "smooth", "soccer",
    "socket", "solar", "soldier", "source", "space", "spark", "special", "speech",
    "spider", "spirit", "splash", "spring", "square", "stable", "standard", "star",
    "status", "steady", "stone", "stream", "street", "strike", "string", "strong",
    "student", "studio", "stumble", "subject", "subway", "sugar", "summer", "sunset",
    "super", "supply", "switch", "symbol", "system", "table", "target", "teacher",
    "temple", "tenant", "tennis", "theory", "threat", "ticket", "timber", "tissue",
    "today", "toggle", "token", "tomorrow", "tonight", "topic", "tortoise", "total",
    "touch", "tourist", "tower", "trace", "track", "traffic", "train", "travel",
    "treat", "tree", "triangle", "trigger", "triumph", "trophy", "truck", "tunnel",
    "turtle", "twilight", "uncle", "under", "unique", "unit", "universe", "update",
    "urban", "urgent", "user", "vacation", "valley", "value", "vanish", "vapor",
    "vector", "velvet", "venture", "verbal", "verify", "vessel", "victim", "victory",
    "video", "village", "vintage", "violet", "violin", "virtual", "virus", "vision",
    "visual", "vital", "voice", "volume", "vortex", "voyage", "walnut", "warmth",
    "warrior", "watch", "water", "weapon", "weather", "webster", "weekly", "welcome",
    "whisper", "widget", "wildlife", "willow", "window", "winner", "winter", "wizard",
    "wonder", "wooden", "worker", "world", "worship", "worthy", "writer", "yellow",
    "yesterday", "youth", "zebra", "zenith", "zero", "zombie", "zone"
}

# Standard QWERTY keyboard rows and columns for keyboard-walk detection
KEYBOARD_ROWS = [
    "`1234567890-=",
    "~!@#$%^&*()_+",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

# Standard QWERTY keyboard columns (vertical walks)
KEYBOARD_COLS = [
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik,", "9ol.", "0p;/"
]

# Leet-speak character substitutions map
LEET_REPLACEMENTS = {
    "@": "a", "4": "a",
    "8": "b",
    "(": "c",
    "3": "e",
    "9": "g",
    "#": "h",
    "!": "i", "1": "i", "|": "i",
    "0": "o",
    "5": "s", "$": "s",
    "7": "t", "+": "t",
    "2": "z"
}
