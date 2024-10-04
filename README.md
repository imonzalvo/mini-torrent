# Rust BitTorrent Client

## Overview

Welcome to the Rust BitTorrent Client! This project is an implementation of a BitTorrent client written in Rust. The primary goal of this project is to learn about the BitTorrent protocol, gain experience with the Rust programming language, and leverage AI as a resource for solving doubts and enhancing code quality.

## Features

- **Torrent File Parsing**: Read and parse `.torrent` files to extract metadata.
- **Peer Communication**: Implement the peer-to-peer communication protocol.
- **Piece Management**: Download pieces of files, handle data integrity, and support for multiple peers.
- **Tracker Interaction**: Communicate with HTTP and UDP trackers to discover peers.
- **Progress Tracking**: Monitor the download progress and maintain a list of downloaded pieces.

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (version 1.60 or higher)
- [Cargo](https://doc.rust-lang.org/cargo/) (comes with Rust)


### Try it out:

```
cargo run -- test_data/IntroductiontotheSpecialTopiconGrammarInduction,RepresentationofLanguageandLanguageLearning.pdf-71e1c9692c556e252aa7e2f4715c419ee447039b.torrent ./out.pdf
```

```
cargo run -- test_data/ComputerNetworks.pdf-958e2487d2db5f41f9c056bb35cf547edf38528f.torrent ./out.pdf
```
