# Refactoring TODO

## Current Structure
```
src/
├── main.rs  # CLI + all command logic
└── aws.rs   # All AWS functionality (900+ lines)
```

## Target Structure (Professional Rust Layout)
```
src/
├── main.rs           # CLI entry point only
├── commands/         # Command implementations
│   ├── mod.rs
│   ├── ping.rs
│   ├── discover.rs
│   └── scan.rs
├── aws/
│   ├── mod.rs        # AWS module root
│   ├── client.rs     # Shared AWS client/helpers
│   ├── vpc.rs        # VPC topology mapping
│   ├── security.rs   # Security group analysis
│   └── compliance.rs # Compliance checking
└── network/
    ├── mod.rs
    ├── discovery.rs  # Local network discovery
    └── scan.rs       # Port scanning
```

## Benefits
- **Separation of concerns**: Each module has one responsibility
- **Easier testing**: Can test modules independently
- **Better navigation**: Find code faster
- **Parallel development**: Multiple people can work on different modules
- **Reduced compile times**: Cargo only recompiles changed modules

## Steps
1. Extract compliance.rs from aws.rs ✅ (attempted, reverted for now)
2. Extract vpc.rs (map_vpc_topology, export_dot, diff_vpcs)
3. Extract security.rs (analyze_security_groups)
4. Create client.rs for shared helpers (get_vpcs, get_subnets, etc.)
5. Move local network commands to network/ module
6. Slim down main.rs to just CLI parsing

## References
- [Rust Module Best Practices](https://softwarepatternslexicon.com/rust/idiomatic-rust-patterns/module-and-crate-organization-best-practices/)
- [Cargo Book - Project Layout](https://doc.rust-lang.org/cargo/guide/project-layout.html)
