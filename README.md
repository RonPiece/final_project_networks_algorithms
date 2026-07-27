---
jupytext:
  cell_metadata_filter: -all
  formats: ipynb,md
  main_language: python
  text_representation:
    extension: .md
    format_name: markdown
    format_version: '1.3'
    jupytext_version: 1.19.2
---

# Topological Analysis and Vulnerability Identification in Software Supply Chains

**Case Study:** Flowise (AI Agent Orchestration Framework v3.1.2)  
**Course:** Graph Algorithms | Dr. Avner Priel, 2026  
**Team Members:** Ron Blanki, Moty Sakhartov, Idan Dahan  

---

## Project Overview

This project maps and analyzes the software supply chain of the `flowise` ecosystem (v3.1.2) using advanced Network Science methodologies. By modeling package dependencies as a **Directed Graph (`DiGraph`)**, we identify structural vulnerabilities, critical bottlenecks, functional communities, and single points of failure (SPOFs) that could be exploited in targeted cyber attacks (e.g., zero-day exploits, malicious package injections).

The analysis covers **2,138 unique package nodes** and **5,016 directed dependency edges**, combining theoretical graph algorithms with real-world CVE threat intelligence from GitHub Advisories and the Open Source Vulnerability (OSV) database.

---

## Repository Structure

```
final_project_networks_algorithms/
├── final_project_networks_algorithms.ipynb   # Main research notebook containing all 10 analysis phases
├── flowise_dependency_graph_snapshot.json    # Fixed dependency graph API snapshot for deterministic execution
├── flowise_exact_version_advisories.csv      # Fixed advisory snapshot for offline & reproducible execution
├── requirements.txt                          # Python package dependencies
├── README.md                                 # Project documentation & execution guide
└── docs/                                     # Project deliverables directory
    ├── final_report.pdf                      # Final PDF project report
    ├── final_report.docx                     # Final Word project report (.docx)
    └── final_presentation.pdf                # 10-slide final project presentation
```

---

## Running the Project

The project can be executed seamlessly either locally or in Google Colab.

### 1. Local Execution (Cloned Repository)

When running locally from the cloned repository, the notebook loads both fixed snapshot files directly from the root directory via:

```python
GRAPH_CACHE_PATH = Path("flowise_dependency_graph_snapshot.json")
ADVISORY_CACHE_PATH = Path("flowise_exact_version_advisories.csv")
```

No path modifications or manual file uploads are necessary.

1. Clone or download the repository.
2. Install required packages: `pip install -r requirements.txt`
3. Open `final_project_networks_algorithms.ipynb` and select **Run All Cells**.

### 2. Direct Google Colab Execution

If executing directly in Google Colab without cloning the full repository:

1. Open the notebook using the Colab link.
2. Select **Runtime → Run all**.

The notebook automatically:
- Installs missing dependencies (`powerlaw` and `cvss`).
- Detects if `flowise_dependency_graph_snapshot.json` or `flowise_exact_version_advisories.csv` are missing from the Colab runtime and downloads the exact snapshots automatically from GitHub Raw.
- Executes the complete 10-phase analysis deterministically.

By default, the notebook relies on the fixed project snapshots:

```python
REFRESH_GRAPH_DATA = False
REFRESH_ADVISORY_DATA = False
```

> **Note on Refresh Flags:**  
> When set to `False` (default), the notebook relies on the submitted snapshots `flowise_dependency_graph_snapshot.json` and `flowise_exact_version_advisories.csv` to ensure deterministic, fully offline, and fast execution. Setting the flags to `True` queries live APIs (`deps.dev` and OSV) for updated graph metadata and advisories. Since upstream databases are updated continuously, refreshed live results may differ slightly from the submitted report.

---

## Requirements & Installation

The project requires Python 3.9+ and standard scientific computing libraries. All required packages can be installed via:

```bash
pip install -r requirements.txt
```

### Main Dependencies

- **Network Analysis:** `networkx>=3.0`
- **Data & Scientific Computing:** `pandas>=2.0.0`, `numpy>=1.24.0`, `scipy>=1.10.0`
- **Visualization:** `matplotlib>=3.5.0`, `seaborn>=0.12.0`
- **Data Ingestion:** `requests>=2.28.0`, `urllib3>=1.26.0`
- **Statistical Fitting & Security Metrics:**
  - `powerlaw==2.0.0` (Power law and heavy-tail distribution fitting)
  - `cvss==3.6` (CVSS v2/v3/v4 score parsing and severity calculation)

---

## Research Workflow & Project Phases

The notebook is organized into 10 structured analytical phases:

### Phase 1: Environment Initialization & Tooling
- Configures workspace parameters, visualization settings, and auto-installs missing dependencies (`powerlaw==2.0.0`, `cvss==3.6`).

### Phase 2: Data Ingestion & Graph Construction
- Pulls the complete transitive dependency graph for `flowise` (v3.1.2) from Google's Open Source Insights API (`deps.dev`).
- Constructs a directed graph (`DiGraph`) preserving unique package nodes while retaining resolved version arrays as metadata.
- **Phase 2.1:** Renders full ecosystem topology visualization ("The Hairball").

### Phase 3: Topological Centrality Assessment
- Calculates **Betweenness Centrality** to pinpoint critical structural bridges (e.g., `semver`, `kind-of`, `form-data`).
- **Phase 3.1 (Spectral Centrality):** Evaluates PageRank and HITS (Hubs & Authorities) metrics.
- **Phase 3.2 (Harmonic Centrality):** Measures reverse-dependency reach across disconnected or weakly connected components.
- **Phase 3.3 (Correlation Analysis):** Analyzes Spearman and Pearson rank correlations between centrality metrics.

### Phase 4: Local Dependency Impact Visualization
- Constructs and visualizes Ego-Networks ("Blast Radius") around high-centrality bottleneck packages to illustrate local propagation risk.

### Phase 5: Community Detection & Structural Segmentation
- Applies **Clauset-Newman-Moore Greedy Modularity Maximization** and **Louvain** algorithms to group 2,138 packages into distinct functional communities (e.g., HTTP utilities, DB connectors, cryptography, build tooling).
- **Phase 5.2 - 5.4:** Computes Global & Internal **Edge Betweenness Centrality** and performs Girvan–Newman hierarchical community splitting.

### Phase 6: Global Structural Characterization
- **Phase 6.1 - 6.2:** Analyzes In-Degree/Out-Degree distributions and contrasts the ecosystem against an equivalent Erdős–Rényi random graph ensemble.
- **Phase 6.3 (Small-World Properties):** Confirms small-world behavior ($L \sim \ln N$ average path length with high clustering coefficient $C \gg C_{\text{random}}$).
- **Phase 6.4 (Heavy-Tail Statistical Fitting):** Utilizes `powerlaw` log-likelihood ratio tests to compare Power Law vs. Lognormal / Truncated Power Law distributions.

### Phase 7: Robustness Analysis — Targeted Disruption vs. Random Failure
- Simulates targeted cyber attacks (sequentially removing highest Betweenness hubs) vs. random package deprecations.
- Quantifies network degradation by monitoring the collapse of the Largest Weakly Connected Component (LWCC).

### Phase 8: Version-Aware Security Advisory Prioritization
- Cross-references topological graph metrics with empirical GitHub Security Advisories and OSV vulnerability data.
- Integrates CVSS v3/v4 severity vector scoring to prioritize security patches based on combined topological centrality and exploit vulnerability ratings.

### Phase 9: Exploratory Link Prediction
- Computes Jaccard Similarity across package dependency neighborhoods to predict implicit lateral movement risks and dynamic dependency changes.

### Phase 10: Related Work & Academic References
- Synthesizes findings and cites foundational literature in network science, supply chain security, scale-free networks, and software risk mitigation.

---

## Methodological Justification: Algorithm Selection & Rationale

| Decision | Selected Methodology | Theoretical & Practical Justification | Alternative Considered & Drawbacks |
| :--- | :--- | :--- | :--- |
| **Graph Model** | **Directed Graph (`nx.DiGraph`)** | Dependency risk flows strictly one-way: if package $A$ depends on $B$, a zero-day in $B$ compromises $A$, but not vice versa. | **Undirected Graph:** Creates false bidirectional paths, leading to inaccurate blast radius calculations. |
| **Centrality Metric** | **Betweenness Centrality** | Identifies "bridge" packages connecting distinct functional domains. Compromising a high-betweenness bridge maximizes attack blast radius. | **In-Degree Centrality:** High degree packages may be isolated within a single domain; high betweenness packages represent true single points of failure. |
| **Community Detection** | **Greedy Modularity Maximization** | Time complexity $O(N \log^2 N)$ allows fast functional segmentation of 2,150+ packages. | **Classic Girvan-Newman:** $O(E^2 N)$ computation is prohibitively slow for large supply chain graphs. |

---

## Authors & Citation

- **Ron Blanki**
- **Moty Sakhartov**
- **Idan Dahan**

**Academic Supervisor:** Dr. Avner Priel (2026)  
**Institution:** Dept. of Computer Science / Network Algorithms Research
