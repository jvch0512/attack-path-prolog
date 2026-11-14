:- use_module(library(plunit)).
:- use_module(library(process)).
:- use_module(library(readutil)).
:- consult('../src/attack_path.pl').

facts(Text) :- tmp_file_stream(text, F, S), write(S, Text), close(S), load_facts(F, E), E == [].
paths(Max, Ps) :- all_paths(Max, Ps).

run_cli(Args, Out, Code) :-
    process_create(path(sh), ['-c', Args], [stdout(pipe(O)), stderr(null), process(Pid)]),
    read_string(O, _, Out), close(O), process_wait(Pid, exit(Code)).

:- begin_tests(attack).

test(single_path) :-
    facts("asset(a,dmz,normal). asset(b,data,crown). exposed(a,http). vuln(a,c1,rce). link(a,b,network). vuln(b,c2,rce)."),
    paths(6, Ps), Ps == [[a,b]].
test(entry_needs_exploitable_vuln) :-
    facts("asset(a,dmz,normal). asset(b,data,crown). exposed(a,http). vuln(a,c1,info_leak). link(a,b,token)."),
    paths(6, []).
test(unexposed_host_is_not_entry) :-
    facts("asset(a,dmz,normal). asset(b,data,crown). vuln(a,c1,rce). link(a,b,token)."),
    paths(6, []).
test(network_link_needs_target_vuln) :-
    facts("asset(a,dmz,normal). asset(b,data,crown). exposed(a,http). vuln(a,c1,rce). link(a,b,network)."),
    paths(6, []).
test(info_leak_does_not_allow_lateral_move) :-
    facts("asset(a,dmz,normal). asset(b,data,crown). exposed(a,http). vuln(a,c1,rce). link(a,b,network). vuln(b,c2,info_leak)."),
    paths(6, []).
test(privesc_allows_lateral_move) :-
    facts("asset(a,dmz,normal). asset(b,data,crown). exposed(a,http). vuln(a,c1,rce). link(a,b,network). vuln(b,c2,privesc)."),
    paths(6, [[a,b]]).
test(trust_link_needs_no_vuln) :-
    forall(member(V, [ssh_key,password,token,kerberos,trust]),
           ( format(string(T), "asset(a,dmz,normal). asset(b,data,crown). exposed(a,http). vuln(a,c1,rce). link(a,b,~w).", [V]),
             facts(T), paths(6, [[a,b]]) )).
test(hop_limit) :-
    facts("asset(a,x,normal). asset(b,x,normal). asset(c,x,normal). asset(d,x,crown). exposed(a,h). vuln(a,c1,rce). link(a,b,token). link(b,c,token). link(c,d,token)."),
    paths(2, []), paths(3, [[a,b,c,d]]).
test(cycles_terminate) :-
    facts("asset(a,x,normal). asset(b,x,normal). asset(c,x,crown). exposed(a,h). vuln(a,c1,rce). link(a,b,token). link(b,a,token). link(b,c,token)."),
    paths(6, [[a,b,c]]).
test(shortest_first) :-
    facts("asset(a,x,normal). asset(b,x,normal). asset(c,x,crown). exposed(a,h). vuln(a,c1,rce). link(a,b,token). link(b,c,token). link(a,c,token)."),
    paths(6, [[a,c],[a,b,c]]).
test(stops_at_first_crown) :-
    facts("asset(a,x,crown). asset(b,x,crown). exposed(a,h). vuln(a,c1,rce). link(a,b,token)."),
    paths(6, [[a]]).
test(severity_by_hops) :-
    path_severity([a,b], critical), path_severity([a,b,c], critical),
    path_severity([a,b,c,d], high), path_severity([a,b,c,d,e], medium), path_severity([a,b,c,d,e,f], low).
test(choke_points, [nondet]) :-
    facts("asset(a,x,normal). asset(m,x,normal). asset(b,x,normal). asset(c,x,crown). asset(d,x,crown). exposed(a,h). vuln(a,c1,rce). link(a,m,token). link(m,c,token). link(m,d,token). link(a,b,token). link(b,c,token)."),
    paths(6, Ps), chokes(Ps, Cs), Cs = [3-a, 2-m|_].
test(no_choke_with_single_path) :-
    facts("asset(a,x,normal). asset(b,x,crown). exposed(a,h). vuln(a,c1,rce). link(a,b,token)."),
    paths(6, Ps), chokes(Ps, []).
test(findings_sorted, [nondet]) :-
    facts("asset(a,x,normal). asset(b,x,normal). asset(c,x,crown). exposed(a,h). vuln(a,c1,rce). link(a,b,token). link(b,c,token). link(a,c,token)."),
    findings(6, _, [f(S1,_,_,_)|_]), S1 == critical.
test(note_lists_entry_exploit, [nondet]) :-
    facts("asset(a,x,normal). asset(b,x,crown). exposed(a,h). vuln(a,'CVE-1',rce). link(a,b,token)."),
    step_notes([a,b], N), sub_atom(N, _, _, _, 'a exploited via CVE-1'), sub_atom(N, _, _, _, 'a -> b by token').
test(directives_rejected) :-
    tmp_file_stream(text, F, S), write(S, ":- shell(true).\nasset(a,x,normal).\nfoo(bar).\n"), close(S),
    load_facts(F, E), length(E, 2), E = [rejected(_), rejected(_)],
    \+ asset(shell, _, _).
test(syntax_error_reported) :-
    tmp_file_stream(text, F, S), write(S, "asset(a,x,normal\nasset(b,x,crown).\n"), close(S),
    load_facts(F, E), E = [syntax(_)|_].
test(missing_file) :- load_facts('/no/such/file.facts', [file_not_found(_)]).
test(reload_replaces_facts) :-
    facts("asset(a,x,crown)."), facts("asset(b,x,crown)."), \+ asset(a,_,_), asset(b,_,crown).

test(cli_exit_codes) :-
    run_cli('../bin/attack-path ../examples/estate.facts', _, 0),
    run_cli('../bin/attack-path ../examples/estate.facts --fail-on critical', _, 1),
    run_cli('../bin/attack-path ../examples/estate.facts --fail-on any --max-hops 1', _, 0),
    run_cli('../bin/attack-path /no/such/file', _, 2),
    run_cli('../bin/attack-path', _, 2),
    run_cli('../bin/attack-path ../examples/estate.facts --bogus', _, 2),
    run_cli('../bin/attack-path ../examples/estate.facts --max-hops 99', _, 2).
test(cli_tsv, [nondet]) :-
    run_cli('../bin/attack-path ../examples/estate.facts --tsv', Out, 0),
    sub_string(Out, 0, _, _, "# 4 attack paths, 7 findings"),
    sub_string(Out, _, _, _, "critical\tPATH\tinternet -> web1 -> files1 -> db1\t").

:- end_tests(attack).
