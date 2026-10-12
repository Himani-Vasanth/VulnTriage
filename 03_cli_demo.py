"""
VulnTriage CLI demo: paste a vulnerability description, get a risk score,
a patch-priority tier, and the words that drove the score.

Usage:
    python 03_cli_demo.py
"""
from vulntriage_lib import score_description

EXAMPLES = [
    ("High-risk example",
     "A remote code execution vulnerability exists due to improper input "
     "validation. An unauthenticated remote attacker can execute arbitrary "
     "code via a crafted network request without user interaction."),
    ("Low-risk example",
     "A local user with physical access to the device could view a "
     "diagnostic log file containing non-sensitive configuration data."),
]


def print_result(desc, result):
    print(f"\nDescription: {desc[:100]}{'...' if len(desc) > 100 else ''}")
    print(f"  Risk score:  {result['score']:.3f}")
    print(f"  Tier:        {result['tier']}")
    if result["raising_terms"]:
        print("  Raises risk: " + ", ".join(t for t, _ in result["raising_terms"]))
    if result["lowering_terms"]:
        print("  Lowers risk: " + ", ".join(t for t, _ in result["lowering_terms"]))


def main():
    print("VulnTriage CLI demo\n")
    for label, desc in EXAMPLES:
        print(f"--- {label} ---")
        print_result(desc, score_description(desc))

    print("\nPaste a CVE description to score it (blank line or 'quit' to exit).")
    while True:
        try:
            desc = input("\n> ").strip()
        except EOFError:
            break
        if desc.lower() in ("quit", "exit", ""):
            break
        print_result(desc, score_description(desc))


if __name__ == "__main__":
    main()
