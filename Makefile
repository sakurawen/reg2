reg:
	python ttx_reg.py reg $(TAG)
reg2:
	python ttx_reg2.py reg $(TAG)
check:
	python email_checker.py $(TAG)
check2:
	python email_checker2.py $(TAG)
balance:
	python ttx_reg.py balance $(TAG)
email:
	python email_code_reader.py $(TAG)
