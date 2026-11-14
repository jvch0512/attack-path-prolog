% attack-path: reasons over a small fact base to find paths from the internet to crown assets.
:- use_module(library(lists)).
:- use_module(library(apply)).
:- dynamic asset/3, exposed/2, vuln/3, link/3.

allowed(asset(_, _, _)).
allowed(exposed(_, _)).
allowed(vuln(_, _, _)).
allowed(link(_, _, _)).

trust_via(ssh_key). trust_via(password). trust_via(token). trust_via(kerberos). trust_via(trust).
exploitable(rce). exploitable(auth_bypass).
lateral(rce). lateral(auth_bypass). lateral(privesc).

%% load_facts(+File, -Errors): data only, directives and rules are rejected.
load_facts(File, Errors) :-
    retractall(asset(_, _, _)), retractall(exposed(_, _)), retractall(vuln(_, _, _)), retractall(link(_, _, _)),
    catch(setup_call_cleanup(open(File, read, S), read_all(S, 1, Errors), close(S)),
          error(existence_error(_, _), _), Errors = [file_not_found(File)]).

read_all(S, N, Errors) :-
    catch(read_term(S, T, [syntax_errors(error)]), error(syntax_error(E), _), (T = '$syntax'(E))),
    (   T == end_of_file -> Errors = []
    ;   T = '$syntax'(E) -> Errors = [syntax(E)|R], read_all_skip(S, N, R)
    ;   allowed(T) -> assertz(T), N1 is N + 1, read_all(S, N1, Errors)
    ;   Errors = [rejected(T)|R], N1 is N + 1, read_all(S, N1, R)
    ).
read_all_skip(S, N, Errors) :- N1 is N + 1, read_all(S, N1, Errors).

entry(H) :- exposed(H, _), vuln(H, _, K), exploitable(K).

step(From, To, Via) :-
    link(From, To, Via),
    (   trust_via(Via) -> true
    ;   vuln(To, _, K), lateral(K) -> true
    ).

%% path(+MaxHops, -Path): Path is a list of hosts from an entry to a crown asset.
path(Max, [Entry|Rest]) :-
    entry(Entry),
    walk(Entry, [Entry], Max, Rest0),
    Rest = Rest0.
walk(H, _, _, []) :- asset(H, _, crown), !.
walk(H, Seen, Left, [Next|Rest]) :-
    Left > 0,
    step(H, Next, _),
    \+ memberchk(Next, Seen),
    Left1 is Left - 1,
    walk(Next, [Next|Seen], Left1, Rest).

all_paths(Max, Paths) :-
    findall(P, path(Max, P), Ps0),
    sort(Ps0, Ps1),
    predsort(by_len, Ps1, Paths).
by_len(O, A, B) :- length(A, LA), length(B, LB), compare(O0, LA-A, LB-B), (O0 = (=) -> O = (<) ; O = O0).

path_severity(P, S) :-
    length(P, L), Hops is L - 1,    % hops counted from the first compromised host
    (   Hops =< 2 -> S = critical
    ;   Hops =< 3 -> S = high
    ;   Hops =< 4 -> S = medium
    ;   S = low ).

path_text(P, T) :- atomic_list_concat([internet|P], ' -> ', T).

step_notes(P, Notes) :-
    P = [H|_],
    findall(N, (vuln(H, Id, K), exploitable(K), format(atom(N), '~w exploited via ~w (~w)', [H, Id, K])), Entry0),
    ( Entry0 = [E|_] -> Entry = [E] ; Entry = [] ),
    findall(N, (append(_, [A, B|_], P), hop_note(A, B, N)), Hops),
    append(Entry, Hops, All),
    atomic_list_concat(All, '; ', Notes).
hop_note(A, B, N) :-
    link(A, B, Via),
    (   trust_via(Via) -> format(atom(N), '~w -> ~w by ~w', [A, B, Via])
    ;   vuln(B, Id, K), lateral(K), format(atom(N), '~w -> ~w via ~w (~w)', [A, B, Id, K]) ), !.

%% choke points: hosts on at least half of the paths (and at least two paths).
chokes(Paths, Chokes) :-
    length(Paths, N), N >= 2,
    append(Paths, All), sort(All, Hosts),
    findall(C-H, (member(H, Hosts), \+ asset(H, _, crown),
                  aggregate_all(count, (member(P, Paths), memberchk(H, P)), C), C * 2 >= N), Cs),
    sort(0, @>=, Cs, Chokes).
chokes(_, []).

findings(Max, Paths, Fs) :-
    all_paths(Max, Paths),
    findall(f(S, 'PATH', W, M), (member(P, Paths), path_severity(P, S), path_text(P, W), step_notes(P, M)), PF),
    length(Paths, N),
    chokes(Paths, Cs),
    findall(f(high, 'CHOKE', H, M), (member(C-H, Cs), format(atom(M), 'sits on ~w of ~w paths: fixing or isolating it cuts them', [C, N])), CF),
    append(PF, CF, Fs0),
    predsort(by_sev, Fs0, Fs).
sev_rank(critical, 0). sev_rank(high, 1). sev_rank(medium, 2). sev_rank(low, 3).
by_sev(O, f(S1, R1, W1, _), f(S2, R2, W2, _)) :-
    sev_rank(S1, A), sev_rank(S2, B),
    compare(O0, A-R1-W1, B-R2-W2), (O0 = (=) -> O = (<) ; O = O0).

main :-
    current_prolog_flag(argv, Argv),
    (   parse_args(Argv, File, Opts) -> true ; usage ),
    load_facts(File, Errors),
    (   Errors == [] -> true
    ;   forall(member(E, Errors), format(user_error, 'error: ~q~n', [E])), halt(2) ),
    option(max_hops(Max), Opts),
    findings(Max, Paths, Fs),
    length(Paths, NP), length(Fs, NF),
    (   option(tsv(true), Opts)
    ->  format('# ~w attack paths, ~w findings~n', [NP, NF]),
        forall(member(f(S, R, W, M), Fs), format('~w\t~w\t~w\t~w~n', [S, R, W, M]))
    ;   format('~w attack paths, ~w findings~n', [NP, NF]),
        forall(member(f(S, R, W, M), Fs), (upcase_atom(S, U), format('~w~t~10|~w ~w~n          ~w~n', [U, R, W, M])))
    ),
    option(fail_on(F), Opts),
    (   F == none -> halt(0)
    ;   fail_floor(F, Floor), member(f(S, _, _, _), Fs), sev_rank(S, K), K =< Floor -> halt(1)
    ;   halt(0) ).

fail_floor(critical, 0). fail_floor(high, 1). fail_floor(any, 3).

usage :-
    format(user_error, 'usage: attack-path FACTS [--tsv] [--max-hops N] [--fail-on critical|high|any]~nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.~n', []),
    halt(2).

parse_args([File|Rest], File, Opts) :- \+ sub_atom(File, 0, 1, _, '-'), parse_opts(Rest, [max_hops(6), tsv(false), fail_on(none)], Opts).
parse_opts([], O, O).
parse_opts(['--tsv'|T], O0, O) :- sel(tsv(_), tsv(true), O0, O1), parse_opts(T, O1, O).
parse_opts(['--max-hops', N|T], O0, O) :- atom_number(N, V), integer(V), V >= 1, V =< 12, sel(max_hops(_), max_hops(V), O0, O1), parse_opts(T, O1, O).
parse_opts(['--fail-on', F|T], O0, O) :- memberchk(F, [critical, high, any]), sel(fail_on(_), fail_on(F), O0, O1), parse_opts(T, O1, O).
sel(Old, New, L0, L) :- select(Old, L0, L1), L = [New|L1].
