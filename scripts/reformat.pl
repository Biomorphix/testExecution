while(<>) {
  if (/\-\-\-/) {
  	next;
  }
  if (/^\-/) {
  	s/^\-/  \-/;
  }
  print;
}

