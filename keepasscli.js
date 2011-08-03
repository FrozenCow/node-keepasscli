var keepass = require('./keepass'),
	path = require('path'),
	spawn = require('child_process').spawn,
	exec = require('child_process').exec,
	notify = require('libnotify').notify;

function readPassword(result) {
	require('tty').setRawMode(true);
	process.stdin.resume();
	var r = '';
	process.stderr.write('Password: ');
	process.stdin.on('keypress', function (chunk, key) {
		switch(chunk) {
			case "\n": case "\r": case "\u0004": 	
				// quit input mode
				require('tty').setRawMode(false);
				process.stdin.pause();
				process.stdout.write("\n");
				
				// run callback
				result(r);
				break;
			
			// backspace
			case "\u007f":
				r = r.substr(0, r.length-1);
				break;
			
			// empty input / send null to callback
			case "\u0003": // CRTL + C
			//case "\u001b": // escape
				process.exit();
				break;
			default:
				r += chunk;
				break;
		}
	});
}

function main(args) {
	var databaseFile;
	var userKeys = [];
	var filters = [];
	var actions = [];
	
	function eachNext(arr, handler, next) {
		(function nextItem() {
			var item = arr.shift();
			if (item) {
				handler(item, nextItem);
			} else { // last
				next();
			}
		})();
	}
	
	eachNext(args, parseArgument, readDatabase);
	function parseArgument(arg, next) {
		if (arg[0] !== '-') {
			databaseFile = arg;
			return next();
		}
		({	p: function() {
				readPassword(function(pw) {
					userKeys.push(keepass.userPassword(pw));
					next();
				});
			},
			f: function() {
				var filter = args.shift().split(':', 2);
				var filterName = filter[0];
				var filterValue = filter[1];
				filters.push(function(e) {
					if (e[filterName]) {
						var value = e[filterName].apply(e);
						return (value && value.toLowerCase().indexOf(filterValue) >= 0);
					} else {
						return false;
					}
				});
				next();
			},
			n: function() {
				var left = parseInt(args.shift());
				filters.push(function(e) {
					return left > 0 && left-- && true;
				});
				next();
			},
			'1': function() {
				var left = 1;
				filters.push(function(e) {
					return left > 0 && left-- && true;
				});
				next();
			},
			o: function() {
				var names = args.shift();
				actions.push(function(e, n) {
					names.split(',').forEach(function(name) {
						if (e[name]) {
							process.stdout.write(e[name].apply(e));
							process.stdout.write('\t');
						}
					});
					process.stdout.write('\n');
					n();
				});
				next();
			},
			t: function() {
				var text = args.shift();
				actions.push(function(e, n) {
					process.stdout.write(text + '\n');
					n();
				});
				next();
			},
			c: function() {
				var name = args.shift();
				actions.push(function(e, n) {
					spawn('notify-send', [ '-c', 'keepass', '-t', '5000', name + ' was copied to clipboard' ]);
					var value = '';
					if (e[name]) { value = e[name].apply(e); }
					var cmd = './clipboard "' + value + '"';
					var clip = exec(cmd, function() {
						n();
					});
				});
				next();
			},
			w: function() {
				var time = parseInt(args.shift());
				actions.push(function(e, n) {
					setTimeout(n, time);
				});
				next();
			}
		}[arg.substr(1)] || function() {
			console.error('Invalid option', arg);
			process.exit(1);
		})();
	}
	
	function readDatabase() {
		keepass.readDatabase(userKeys, databaseFile, handleDatabase, function(error) {
			if (error instanceof Error) {
				console.error(error.message);
			} else if (typeof error === 'string') {
				console.error(error);
			} else {
				console.error('Unknown error:', error);
			}
			process.exit(1);
		});
	}
	
	function handleDatabase(db) {
		handlegroup(db.root(), end);
		
		function handlegroup(group, next) {
			eachNext(group.groups(), handlegroup, function() {
				eachNext(group.entries(), handleentry, next);
			});
		}
		
		function filter(entry) {
			return filters.every(function(f) { return f(entry); });
		}
		
		function handleentry(entry, next) {
			if (filter(entry)) {
				eachNext(actions.slice(0), function(action, next) {
					action(entry, next);
				}, next);
			} else {
				next();
			}
		}
	}
	
	function end() {
		
	}
	/*keepass.readDatabase(userKeys, databaseFile, handleDatabase, function(error) {
		if (error instanceof Error) {
			console.error(error.message);
		} else if (typeof error === 'string') {
			console.error(error);
		} else {
			console.error('Unknown error:', error);
		}
		process.exit(1);
	});
	
	function handleDatabase(db) {
		(function handlegroup(group) {
			group.groups().forEach(handlegroup);
			group.entries().forEach(handleentry);
		})(db.root());
		
		function filter(entry) {
			return filters.every(function(f) { return f(entry); });
		}
		
		function handleentry(entry) {
			if (filter(entry)) {
				var leftoverActions = actions.slice(0);
				function next() {
					var action = leftoverActions.shift();
					action(entry, next);
				}
			}
		}
	}*/
}

main(process.argv.slice(2));
