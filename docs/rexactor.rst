RExACtor
==========

RExACtor is a Regular Expression Apriori Constructor tool for extracting
frequent substring tokens from packet payloads and automatically generating
regular expression signatures. RExACtor operates in two modes: **token** and
**regex**.


Token Mode
~~~~~~~~~~~

In token mode, the `Apriori Algorithm <https://efficient-apriori.readthedocs.io/en/latest/>`_ is used to
extract substrings of two characters or more from packet payloads which meet a
minimum threshold of support (0.0 - 1.0). Token mode requires a minimum threshold
parameter and an absolute file path to either a PCAP, PCAPNG, or CSV file. If a
PCAP/PCAPNG file is provided, `TaPCAP <https://tapcap.readthedocs.io/en/latest/>`_
will be applied first and a local output file used for mining.

Regular Expression Mode
~~~~~~~~~~~~~~~~~~~~~~~~

In regex mode, the same algorithm is used to extract substrings of two characters
or more from packet payloads. Additionally, position frequency tables are used to
give context to tokens and characters to determine any single-byte tokens at a fixed
position, or any common prefixes or suffixes which meet a minimum threshold of
support (0.0 - 1.0). Regex mode requires a minimum threshold parameter for prefixes
and a minimum threshold parameter for suffixes and an absolute file path to
either a PCAP, PCAPNG, or CSV file. If a PCAP/PCAPNG file is provided, `TaPCAP <https://tapcap.readthedocs.io/en/latest/>`_
will be applied first and a local output file used for mining.

Frequent tokens are added to regex capture groups based on positional context
to either the prefix or suffix of the output regex. RExACtor uses global substring
sequence alignment enhanced with a novel encoding schema to determine character
classes of variable and fixed length between the prefix and suffix. Regexes
generated by this tool follow `Posix <https://www.regular-expressions.info/posixbrackets.html>`_
conventions.

Supported Operators
~~~~~~~~~~~~~~~~~~~~

.. list-table:: Supported Regex Operators
   :widths: 20 10 50
   :header-rows: 1

   * - Type
     - Symbol
     - Definition
   * - Character Class
     - .
     - Matches any character.
   * -
     - []
     - Matches any character contained in the brackets.
   * -
     - [^]
     - Matches any character not contained in the brackets.
   * -
     - \\d
     - Matches any digit (0-9).
   * -
     - \\s
     - Matches any whitespace character.
   * -
     - \\w
     - Matches any word character (letters, numbers, and underscores).
   * -
     - \\D
     - Matches any non-digit (0-9).
   * -
     - \\S
     - Matches any non-whitespace character.
   * -
     - \\W
     - Matches any non-word character (not letters, numbers, and underscores).
   * - Quantifier
     - \*
     - Matches zero or more times.
   * -
     - ?
     - Matches at most one time.
   * -
     - \+
     - Matches one or more times.
   * -
     - {`m`, `n`}
     - Matches between `m` and `n` times.
   * -
     - {`m`,}
     - Matches 'm' or more times.
   * -
     - {,`n`}
     - Matches at most `n` times.
   * - Other
     - ^
     - Matches at the beginning (left-anchor) of the data.
   * -
     - $
     - Matches at the end (right-anchor) of the data.
   * -
     - ()
     - Capture group.
   * -
     - \|
     - Logical OR operator.





Installation
~~~~~~~~~~~~~

At the command line::

    easy_install rexactor

Or, if you have pip installed::

    pip install rexactor

Usage
~~~~~~

Users can provide a PCAP file to RExACtor in order to generate signatures,
or a CSV file following the `TaPCAP <https://tapcap.readthedocs.io/en/latest/>`_ output schema. Once run,
users will be prompted to select token or regex mode. Then, according
to the selection they will be required to input a single threshold of Support
or one for prefix and suffix, respectively. Any generated tokens or
regular expressions will be printed to standard output.

.. code-block ::

  RExACtor: A Regular Expression Apriori Constructor
  Prefix frequency threshold (0.0 - 1.0)? 0.3
  Suffix frequency threshold (0.0 - 1.0)? 0.3
  File input path (PCAP, PCAPNG, or CSV)? /Users/mkapoor1/Desktop/short_pop.csv
  Mining tokens...
  Prefixes:  ^(S: +OK |C: |S: |S: +OK)
  Suffixes:
  aligning...
  Regex: ^(S: +OK |C: |S: |S: +OK).{0,9457}

**Publication:**

Kapoor, M., Fuchs, G., Quance, J.
`RExACtor: Automatic Regular Expression Signature Generation for Stateless
Packet Inspection. <https://ieeexplore.ieee.org/document/9685959>`_
In proceedings of IEEE 20th International Symposium
on Network Computing and Applications (NCA). 23-26 November, 2021.
