/*
 * suites.h — Registry of test-suite entry points.
 *
 * Every suite_*(void) entry point in the tree is declared here, across both
 * runners: tests/test_main.c and tests/repro/repro_main.c. One registry
 * rather than one per runner, because several repro files build into both
 * binaries and would otherwise need duplicate declarations.
 *
 * Each suite .c file includes this header so its suite_*(void) definition
 * is checked against a visible declaration in the same translation unit
 * (required under -Wmissing-prototypes). To add a new suite, add its
 * SUITE(name) definition to a test file, add the matching declaration
 * below in the section for its subsystem, and wire it into the
 * RUN_SELECTED_SUITE list of the runner that drives it.
 *
 * Order and grouping mirror the RUN_SELECTED_SUITE call sequence in
 * test_main.c, which reflects suite execution order.
 */
#ifndef CBM_TESTS_SUITES_H
#define CBM_TESTS_SUITES_H

/* Foundation */
extern void suite_arena(void);
extern void suite_hash_table(void);
extern void suite_dyn_array(void);
extern void suite_str_intern(void);
extern void suite_log(void);
extern void suite_str_util(void);
extern void suite_workspace(void);
extern void suite_platform(void);
extern void suite_diagnostics(void);
extern void suite_subprocess(void);
extern void suite_private_file_lock(void);
extern void suite_lock_registry(void);
extern void suite_dump_verify(void);

/* Existing C code regression tests */
extern void suite_ac(void);
extern void suite_extraction(void);
extern void suite_extraction_inheritance(void);
extern void suite_extraction_imports(void);
extern void suite_parse_coverage(void);
extern void suite_grammar_regression(void);
extern void suite_grammar_labels(void);
extern void suite_grammar_imports(void);

/* Store (M5) */
extern void suite_store_nodes(void);
extern void suite_store_edges(void);
extern void suite_store_search(void);
extern void suite_store_bulk(void);
extern void suite_store_pragmas(void);
extern void suite_store_checkpoint(void);
extern void suite_dump_verify_io(void);

/* Cypher (M6) */
extern void suite_cypher(void);

/* MCP Server (M9) */
extern void suite_mcp(void);
extern void suite_mcp_mutation_guard(void);
extern void suite_index_supervisor(void);

/* Shared MCP daemon coordination + private framing */
extern void suite_daemon(void);
extern void suite_project_lock(void);
extern void suite_version_cohort(void);
extern void suite_daemon_version(void);
extern void suite_daemon_runtime(void);
extern void suite_daemon_application(void);
extern void suite_daemon_frontend(void);
extern void suite_daemon_bootstrap(void);
extern void suite_daemon_ipc(void);

/* Discover (M2) */
extern void suite_language(void);
extern void suite_userconfig(void);
extern void suite_gitignore(void);
extern void suite_git_context(void);
extern void suite_discover(void);

/* Graph Buffer (M7) */
extern void suite_graph_buffer(void);

/* Pipeline (M8) */
extern void suite_registry(void);
extern void suite_pipeline(void);
extern void suite_pipeline_semantic_manifest_repro(void);
extern void suite_call_reference_contract(void);
extern void suite_call_reference_language_complex_contract(void);
extern void suite_repro_call_scope_usages(void);
extern void suite_repro_call_argument_usages(void);
extern void suite_repro_reference_precision(void);
extern void suite_repro_call_argument_matrix_a(void);
extern void suite_repro_call_argument_matrix_b(void);
extern void suite_repro_call_node_behaviors(void);
extern void suite_repro_language_registry(void);
extern void suite_repro_call_node_manifest(void);
extern void suite_repro_lsp_ordered_signatures(void);
extern void suite_repro_lsp_ordered_local(void);
extern void suite_repro_ts_overload_return_chains(void);
extern void suite_repro_harness_cleanup(void);
extern void suite_repro_runner_filter(void);
extern void suite_cross_repo(void);
extern void suite_index_resilience(void);
extern void suite_fqn(void);
extern void suite_route_canon(void);
extern void suite_path_alias(void);

/* Watcher (M10) */
extern void suite_watcher(void);

/* LZ4 + zstd + SQLite writer */
extern void suite_lz4(void);
extern void suite_zstd(void);
extern void suite_sqlite_writer(void);

/* Persistent artifact export/import */
extern void suite_artifact(void);

/* LSP resolvers */
extern void suite_scope(void);
extern void suite_type_rep(void);
extern void suite_go_lsp(void);
extern void suite_c_lsp(void);
extern void suite_php_lsp(void);
extern void suite_cs_lsp(void);
extern void suite_cs_lsp_bench(void);
extern void suite_perl_lsp(void);
extern void suite_py_lsp(void);
extern void suite_kotlin_lsp(void);
extern void suite_rust_lsp(void);
extern void suite_py_lsp_bench(void);
extern void suite_py_lsp_stress(void);
extern void suite_py_lsp_scale(void);
extern void suite_ts_lsp(void);
extern void suite_java_lsp(void);
extern void suite_java_lsp_coverage(void);

/* Architecture + ADR + Louvain */
extern void suite_store_arch(void);

/* Traces helpers */
extern void suite_traces(void);

/* Config link */
extern void suite_configlink(void);

/* Infrastructure scanning */
extern void suite_infrascan(void);

/* CLI (install, update, config) */
extern void suite_cli(void);
extern void suite_agent_clients(void);
extern void suite_agent_profiles(void);
extern void suite_config_json_like(void);
extern void suite_config_toml_edit(void);
extern void suite_config_yaml_edit(void);
extern void suite_config_text_edit(void);
extern void suite_activation_transaction(void);

/* System info + worker pool (parallelism) */
extern void suite_system_info(void);
extern void suite_worker_pool(void);

/* Parallel pipeline */
extern void suite_parallel(void);

/* Promoted lexical-resolution regression contracts. */
extern void suite_repro_lexical_binding_precision(void);

/* mem + arena + slab integration */
extern void suite_slab_alloc(void);
extern void suite_mem(void);

/* UI (config, embedded assets, layout) */
extern void suite_ui(void);

/* UI HTTP server (transport + routing) */
extern void suite_httpd(void);

/* Security defenses */
extern void suite_security(void);

/* YAML parser */
extern void suite_yaml(void);

/* SimHash / SIMILAR_TO */
extern void suite_semantic(void);
extern void suite_ast_profile(void);
extern void suite_simhash(void);

/* Stack overflow regression (GitHub #199) — split a/b/c so no single
 * suite serializes a parallel run (each ~1/3 of the old wall time). */
extern void suite_stack_overflow_a(void);
extern void suite_stack_overflow_b(void);
extern void suite_stack_overflow_c(void);

/* Integration (end-to-end) */
extern void suite_integration(void);

/* Per-language graph contracts (node/edge types, attribution, no-crash) */
extern void suite_lang_contract(void);
extern void suite_edge_imports(void);
extern void suite_edge_structural(void);
extern void suite_lsp_resolution_probe(void);
extern void suite_node_creation_probe(void);
extern void suite_edge_types_probe(void);
extern void suite_convergence_probe(void);
extern void suite_matrix_known_classes(void);
extern void suite_matrix_new_constructs(void);
extern void suite_grammar_probe_a(void);
extern void suite_grammar_probe_b(void);
extern void suite_grammar_probe_c(void);
extern void suite_grammar_probe_d(void);
extern void suite_grammar_probe_e(void);
extern void suite_grammar_probe_f(void);
extern void suite_grammar_probe_g(void);

/* Incremental indexing */
extern void suite_incremental(void);

/* Repro suites — driven by tests/repro/repro_main.c rather than
 * test_main.c. Declared here so the single registry covers every
 * suite entry point in the tree; several of these files build into
 * both runners. */
extern void suite_repro_extraction(void);
extern void suite_repro_grammar_build(void);
extern void suite_repro_grammar_config(void);
extern void suite_repro_grammar_core(void);
extern void suite_repro_grammar_functional(void);
extern void suite_repro_grammar_markup(void);
extern void suite_repro_grammar_misc(void);
extern void suite_repro_grammar_scientific(void);
extern void suite_repro_grammar_scripting(void);
extern void suite_repro_grammar_shells(void);
extern void suite_repro_grammar_systems(void);
extern void suite_repro_grammar_web(void);
extern void suite_repro_invariant_breadth(void);
extern void suite_repro_invariant_calls(void);
extern void suite_repro_invariant_discovery_fqn(void);
extern void suite_repro_invariant_enclosing_parity(void);
extern void suite_repro_invariant_graph(void);
extern void suite_repro_invariant_lsp_rescue(void);
extern void suite_repro_issue221(void);
extern void suite_repro_issue333(void);
extern void suite_repro_issue363(void);
extern void suite_repro_issue382(void);
extern void suite_repro_issue403(void);
extern void suite_repro_issue408(void);
extern void suite_repro_issue409(void);
extern void suite_repro_issue431(void);
extern void suite_repro_issue434(void);
extern void suite_repro_issue471(void);
extern void suite_repro_issue480(void);
extern void suite_repro_issue495(void);
extern void suite_repro_issue510(void);
extern void suite_repro_issue514(void);
extern void suite_repro_issue520(void);
extern void suite_repro_issue521(void);
extern void suite_repro_issue523(void);
extern void suite_repro_issue546(void);
extern void suite_repro_issue548(void);
extern void suite_repro_issue557(void);
extern void suite_repro_issue56(void);
extern void suite_repro_issue570(void);
extern void suite_repro_issue571(void);
extern void suite_repro_issue581(void);
extern void suite_repro_issue607(void);
extern void suite_repro_issue627(void);
extern void suite_repro_issue787(void);
extern void suite_repro_issue842(void);
extern void suite_repro_issue964(void);
extern void suite_repro_lsp_c_cpp(void);
extern void suite_repro_lsp_go_py(void);
extern void suite_repro_lsp_java_cs(void);
extern void suite_repro_lsp_kt_php_rust(void);
extern void suite_repro_lsp_ts(void);
extern void suite_repro_new_cypher_limit_zero(void);
extern void suite_repro_new_py_tuple_unpack(void);
extern void suite_repro_new_ts_class_field_arrow(void);
extern void suite_repro_parallel_determinism(void);
extern void suite_repro_ts_inherited_method(void);

#endif /* CBM_TESTS_SUITES_H */
