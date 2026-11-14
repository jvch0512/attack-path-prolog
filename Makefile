build:
	chmod +x bin/attack-path

test:
	cd tests && swipl -q -g 'run_tests,halt(0)' -t 'halt(1)' test.pl

sample: build
	mkdir -p docs site
	./bin/attack-path examples/estate.facts > docs/sample-output.txt; true
	./bin/attack-path examples/estate.facts --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "attack-path-prolog" "Attack path analysis from a few facts: internet to crown jewels, with choke points. Prolog." "A made-up estate: web, app, jump host, file server, database and a backup server."
