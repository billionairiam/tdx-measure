if [ -z "$prefix" -o ! -e "$prefix" ]; then
	if ! search --file --set=root /.disk/info; then
		search --file --set=root /.disk/mini-info
	fi
	set prefix=($root)/boot/grub
fi
if [ -e $prefix/x86_64-efi/grub.cfg ]; then
	source $prefix/x86_64-efi/grub.cfg
elif [ -e $prefix/grub.cfg ]; then
	source $prefix/grub.cfg
else
	source $cmdpath/grub.cfg
fi
