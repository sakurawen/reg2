reg:
	python ttx_reg.py reg $(TAG)
reg2:
	python txt_reg.py reg csv/$(TAG).csv
check:
	python email_checker.py $(TAG)
check2:
	python email_checker2.py csv/$(TAG).csv
balance:
	python ttx_reg.py balance $(TAG)
email:
	python email_code_reader.py $(TAG)
