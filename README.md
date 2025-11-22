# A Tiny Little Compliance Stack (ATLCS)

This repo contains the API, Githubworkflows, and assets used internally to help facilitate Nabla's compliance-as-code vision without heavy opinionation and allowing clients and users to use their own tools, with the caveat that at the moment they are up for using Github Actions for the main automations. 

## Features

- Lightweight Compliance API – Programmatically interact with compliance controls and frameworks.

- GitHub Actions Workflows – Pre-built workflows to automate compliance tasks and audits.

- Extensible Assets – All controls can be extended and developed iterively and as fast or slow as we need to. 

- Framework-Agnostic – Supports multiple standards and tool stacks (e.g., FedRAMP, Airtable, CMMC) without locking users into a particular toolchain.

Audit-Friendly – Outputs and logs are structured for easy review and reporting.

## Getting Started

1. Clone the repository

```
git clone https://github.com/your-org/atlcs.git
cd mapping-api
```

2. Install dependencies (if applicable)

```
cargo install
```

3. Configure GitHub Actions

- Update secrets and environment variables in your repository.
- Mix and match from the `/workflows` folder into your own `.github/workflows/` and adjust triggers or jobs to fit your use case.

4. Run the API locally

```
cargo run
```

5. Use the compliance assets

- Guideline documents are in the assets/ folder.
- Follow the README in each subfolder for usage instructions.

## Contributing

We welcome contributions! Please adhere to the following guidelines:

- Fork the repository and create a new branch for your feature or fix.
- Write clear, concise commit messages.
- Ensure workflows and scripts maintain compliance accuracy.
- Open a pull request and describe your changes in detail.

## License

This project is licensed under the Apache 2.0 License.

## Disclaimer

ATLCS is provided as-is. While it facilitates compliance automation, responsibility for final compliance verification lies with the user or client. Use in production environments should follow proper testing and review.