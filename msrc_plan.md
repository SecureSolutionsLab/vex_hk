# Microsoft Security Response Center

## Main Links

- Main page: https://msrc.microsoft.com/

- Update guide: https://msrc.microsoft.com/update-guide

- API info (swagger, older): https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json

- API all updates (older): https://api.msrc.microsoft.com/cvrf/v3.0/updates

- API update month example (older): https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2016-Oct

- API new (CSAF): https://msrc.microsoft.com/csaf

- API new example: https://msrc.microsoft.com/csaf/advisories/2025/msrc_cve-2025-24059.json

- CVRF specification from CSAF: https://docs.oasis-open.org/csaf/csaf-cvrf/v1.2/csaf-cvrf-v1.2.html

- CSAF: https://www.csaf.io/

- CSAF rust repository (incomplete): https://github.com/csaf-poc/csaf-rust

## Papers, articles (general)

### Analysis and Aggregation of Vulnerability Databases with Code-Level Data

Author: Pedro Leite Galvão

Source: https://repositorio-aberto.up.pt/bitstream/10216/144796/2/588886.pdf

#### About

Study of data obtained from vulnerability databases for the purpose of creating scanners capable of finding vulnerabilities in software code.

#### Relevant information:

- [Chapter 2] Basic explanation about Security Content Automation Protocol (SCAP) for classification of vulnerability severity. Information about CVE, CWE, CVSS and CPE in this context.
- [Chapter 3] Related work about other vulnerability scanners and studies about information extracted from database entries.
- [Chapter 4] Open and closed databases containing information primarily focused on vulnerabilities affecting visible code. Mostly focused on commits about specific languages.
- [Chapter 6.4] Overlap about common vulnerabilities in different databases.

### The anatomy of a vulnerability database: A systematic mapping study

Authors: Xiaozhou Li, Sergio Moreschini, Zheying Zhang, Fabio Palomba, Davide Taibi

Source: https://www.sciencedirect.com/science/article/pii/S0164121223000742

#### About

Analysis and mapping study of different popular databases, in accordance to specific papers written in reference to them.

#### Relevant information:

 - Extensive references to relevant research particular to a specific vulnerability database. Includes use and analysis of a database and respective data.
 - Mentions MSRC.

Notes: Not much information related to scraping itself, more focused on data analysis.

### Evaluating the Data Inconsistency of Open-Source Vulnerability Repositories

Authors: Yuning Jiang, Manfred Jeusfeld, Jianguo Ding

Source: https://dl.acm.org/doi/abs/10.1145/3465481.3470093

#### About

Mathematical analysis about differences in available information of common open source vulnerability databases.

#### Relevant information:

 - More general evaluation about available information.
 - Mentions MSRC.

### A survey on vulnerability assessment tools and databases for cloud-based web applications

Authors: Kyriakos Kritikos, Kostas Magoutis, Manos Papoutsakis, Sotiris Ioannidis

Source: https://www.sciencedirect.com/science/article/pii/S2590005619300116

#### About

Analysis of vulnerability databases in relation to web applications, focusing on application security and vulnerability scanning tools.

## Papers, articles (MSRC, Microsoft related)

### Generating ICS vulnerability playbooks with open standards

Authors: Philip Empl, Daniel Schlette, Günther Pernul & Lukas Stöger

Source: https://link.springer.com/article/10.1007/s10207-023-00760-5

#### About

Process model of collecting security advisories to help organizations respond to security incidents

#### Relevant information:

- Talks about open security standards like CVRF and CSAF, and differences between the two.
- Details on working with security advisories.
