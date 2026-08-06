"""faramir -- a secret broker for local AI coding agents.

The broker runs credential-bearing commands as its own uid and returns output
with every known secret value replaced by a stable token, so plaintext never
enters the agent's context and therefore never reaches a model provider.

It keeps plaintext out of model context.  It does not contain a compromised
agent -- see the threat model in the README.
"""

__version__ = "1.0.0"
