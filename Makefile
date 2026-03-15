abs_dir := $(shell pwd)
DOCKER_IMAGE ?= rqe-qkd-fv
clean_spthy=./tools/clean_spthy
tamarin=./tools/tamarin-prover
TAMARIN_FLAGS= 
# TAMARIN_FLAGS= -c=100
# TAMARIN_FLAGS=+RTS -N16 -RTS # limit number of CPUs used
# TAMARIN_FLAGS=+RTS -s -M1000000000 -RTS # limit amount of memory used

type=EB
Adv=Network
exec=false
auth=false
secrecy=false
ER=FEC
BO=PostM
M4_FLAGS= --define=type=$(type) --define=Adv=$(Adv) --define=auth=$(auth) --define=secrecy=$(secrecy) --define=exec=$(exec) --define=ER=$(ER) --define=BO=$(BO)

# ifeq ($(Adv), Network)
# 	M4_FLAGS=net
# endif

#  make type=EB auth=true ER=REC BO=PostM Adv=Network prove
#  make type=PM auth=true ER=REC BO=SeqA Adv=MaliciousUser  prove

preprocess:
	m4 ${M4_FLAGS} main.m4 > generated_$(type).spthy
	$(clean_spthy) generated_$(type).spthy

test: preprocess
	${tamarin} ${TAMARIN_FLAGS} --quit-on-warning generated_$(type).spthy

prove: preprocess
	${tamarin} ${TAMARIN_FLAGS} --prove --output=generated_$(type).proof generated_$(type).spthy
# --with-dot=$(abs_dir)/tools/tamarin-cleandot.py
# --with-dot=$(abs_dir)/tools/tamarin-cleandot.py


web: preprocess
	${tamarin} interactive generated_$(type).spthy


gen_proofs:
	chmod a+x ./tools/compile_models ./tools/gen_proofs ./tools/collect ./tools/clean_spthy ./tools/test_models ./tools/check_incompleted ./tools/setup.sh ./tools/maude/*
	./tools/compile_models
	# ./tools/test_models
	time ./tools/gen_proofs | tee run.log
	./tools/collect --output=./output/generated_results.html ./output/

web_proofs: 
	echo $(abs_dir)
	${tamarin} interactive ./output/


all: prove web





clean:
	$(RM) -f generated_*
	$(RM) -f client_session_key.aes

clean_tmp:
	$(RM) -f ./output/*.tmp

clean_theory:
	$(RM) -f ./output/*.spthy
	

clean_proofs:
	$(RM) -f ./output/*.proof

clean_all: clean clean_theory clean_proofs clean_tmp
	$(RM) -f run.log



# ─── Docker targets ──────────────────────────────────────────────────────────
# Build the Docker image (re-run whenever the Dockerfile changes)
docker-build:
	docker compose build

# Run the full proof-generation pipeline inside Docker.
# Outputs land in ./_output/ on the HOST (mounted into the container).
docker-gen-proofs:
	mkdir -p ./_output
	docker compose run --rm tamarin make gen_proofs

# Collect proof summaries into ./_output/generated_results.html
# (Usually run automatically by gen_proofs but available here just in case)
docker-collect:
	mkdir -p ./_output
	docker compose run --rm tamarin ./tools/collect --output=./output/generated_results.html ./output/

# Open an interactive shell inside the container for debugging
docker-shell:
	docker compose run --rm tamarin bash

# Launch Tamarin interactive mode in Docker. Access the GUI at http://127.0.0.1:$(PORT)
# Use with: make docker-web [type=EB|PM] [PORT=3001]
PORT ?= 3001
docker-web:
	mkdir -p ./_output
	docker compose run --rm -p $(PORT):3001 -e type=$(type) tamarin sh -c 'make preprocess && ./tools/tamarin-prover interactive generated_$${type}.spthy'

# Launch Tamarin interactive mode over all proofs in output/. Requires gen_proofs first.
# Access at http://127.0.0.1:$(PORT)
docker-web-proofs:
	mkdir -p ./_output
	docker compose run --rm -p $(PORT):3001 tamarin ./tools/tamarin-prover interactive ./output/

