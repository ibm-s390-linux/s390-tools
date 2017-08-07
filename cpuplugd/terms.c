/*
 * cpuplugd - Linux for System z Hotplug Daemon
 *
 * Term parsing
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "cpuplugd.h"

static enum op_prio op_prio_table[] =
{
	[OP_NEG] = OP_PRIO_ADD,
	[OP_GREATER] = OP_PRIO_CMP,
	[OP_LESSER] = OP_PRIO_CMP,
	[OP_PLUS] = OP_PRIO_ADD,
	[OP_MINUS] = OP_PRIO_ADD,
	[OP_MULT] = OP_PRIO_MULT,
	[OP_DIV] = OP_PRIO_MULT,
	[OP_AND] = OP_PRIO_AND,
	[OP_OR] = OP_PRIO_OR,
};

static void free_term(struct term *fn)
{
	if (!fn)
		return;
	switch (fn->op) {
	case OP_SYMBOL_LOADAVG:
	case OP_SYMBOL_RUNABLE:
	case OP_SYMBOL_CPUS:
	case OP_SYMBOL_USER:
	case OP_SYMBOL_NICE:
	case OP_SYMBOL_SYSTEM:
	case OP_SYMBOL_IDLE:
	case OP_SYMBOL_IOWAIT:
	case OP_SYMBOL_IRQ:
	case OP_SYMBOL_SOFTIRQ:
	case OP_SYMBOL_STEAL:
	case OP_SYMBOL_GUEST:
	case OP_SYMBOL_GUEST_NICE:
	case OP_CONST:
		free(fn);
		break;
	case OP_NEG:
	case OP_NOT:
		free_term(fn->left);
		free(fn);
		break;
	case OP_GREATER:
	case OP_LESSER:
	case OP_PLUS:
	case OP_MINUS:
	case OP_MULT:
	case OP_DIV:
	case OP_AND:
		free_term(fn->left);
		free_term(fn->right);
		free(fn);
		break;
	case OP_OR:
		free_term(fn->left);
		free_term(fn->right);
		free(fn);
		break;
	default:
		break;
	}
}

void print_term(struct term *fn)
{
	switch (fn->op) {
	case OP_SYMBOL_LOADAVG:
		printf("loadavg");
		break;
	case OP_SYMBOL_RUNABLE:
		printf("runnable_proc");
		break;
	case OP_SYMBOL_CPUS:
		printf("onumcpus");
		break;
	case OP_SYMBOL_USER:
		printf("user");
		break;
	case OP_SYMBOL_NICE:
		printf("nice");
		break;
	case OP_SYMBOL_SYSTEM:
		printf("system");
		break;
	case OP_SYMBOL_IDLE:
		printf("idle");
		break;
	case OP_SYMBOL_IOWAIT:
		printf("iowait");
		break;
	case OP_SYMBOL_IRQ:
		printf("irq");
		break;
	case OP_SYMBOL_SOFTIRQ:
		printf("softirq");
		break;
	case OP_SYMBOL_STEAL:
		printf("steal");
		break;
	case OP_SYMBOL_GUEST:
		printf("guest");
		break;
	case OP_SYMBOL_GUEST_NICE:
		printf("guest_nice");
		break;
	case OP_SYMBOL_SWAPRATE:
		printf("swaprate");
		break;
	case OP_SYMBOL_FREEMEM:
		printf("freemem");
		break;
	case OP_SYMBOL_APCR:
		printf("apcr");
		break;
	case OP_SYMBOL_MEMINFO:
		printf("meminfo.%s[%u]", fn->proc_name, fn->index);
		break;
	case OP_SYMBOL_VMSTAT:
		printf("vmstat.%s[%u]", fn->proc_name, fn->index);
		break;
	case OP_SYMBOL_CPUSTAT:
		printf("cpustat.%s[%u]", fn->proc_name, fn->index);
		break;
	case OP_SYMBOL_TIME:
		printf("time[%u]", fn->index);
		break;
	case OP_CONST:
		printf("%f", fn->value);
		break;
	case OP_NEG:
		printf("-(");
		print_term(fn->left);
		printf(")");
		break;
	case OP_NOT:
		printf("!(");
		print_term(fn->left);
		printf(")");
		break;
	case OP_PLUS:
	case OP_MINUS:
	case OP_MULT:
	case OP_DIV:
	case OP_AND:
	case OP_OR:
	case OP_GREATER:
	case OP_LESSER:
		printf("(");
		print_term(fn->left);
		switch (fn->op) {
		case OP_AND:
			printf(") & (");
			break;
		case OP_OR:
			printf(") | (");
			break;
		case OP_GREATER:
			printf(") > (");
			break;
		case OP_LESSER:
			printf(") < (");
			break;
		case OP_PLUS:
			printf(") + (");
			break;
		case OP_MINUS:
			printf(") - (");
			break;
		case OP_MULT:
			printf(") * (");
			break;
		case OP_DIV:
			printf(") / (");
			break;
// TODO OP_CONST, OP_SYMBOL_LOADAVG, ... possible here???
		case OP_CONST:
			printf("%f", fn->value);
			break;
		case OP_SYMBOL_LOADAVG:
		case OP_SYMBOL_RUNABLE:
		case OP_SYMBOL_CPUS:
		case OP_SYMBOL_USER:
		case OP_SYMBOL_NICE:
		case OP_SYMBOL_SYSTEM:
		case OP_SYMBOL_IDLE:
		case OP_SYMBOL_IOWAIT:
		case OP_SYMBOL_IRQ:
		case OP_SYMBOL_SOFTIRQ:
		case OP_SYMBOL_STEAL:
		case OP_SYMBOL_GUEST:
		case OP_SYMBOL_GUEST_NICE:
		case OP_SYMBOL_APCR:
		case OP_SYMBOL_SWAPRATE:
		case OP_SYMBOL_FREEMEM:
		case OP_SYMBOL_MEMINFO:	// TODO use default: ???
		case OP_SYMBOL_VMSTAT:	// TODO use default: ???
		case OP_SYMBOL_CPUSTAT:	// TODO use default: ???
		case OP_SYMBOL_TIME:	// TODO use default: ???
		case OP_NEG:
		case OP_NOT:
		case VAR_LOAD:
		case VAR_RUN:
		case VAR_ONLINE:
			break;
		}
		print_term(fn->right);
		printf(")");
		break;
	case VAR_LOAD:
	case VAR_RUN:
	case VAR_ONLINE:
		break;
	}
}

static struct term *parse_var_term(char **p)
{
	char *s, *var_rvalue;
	struct term *fn;
	unsigned int length;
	char var_name[MAX_VARNAME + 1];

	s = *p;
	length = 0;
	fn = NULL;
	while (isalnum(*s) || *s == '_') {
		var_name[length] = *s;
		length++;
		s++;
		if (length > MAX_VARNAME)
			cpuplugd_exit("Variable name too long (max. length is "
				      "%i chars): %s\n", MAX_VARNAME, *p);
	}
	var_name[length] = '\0';
	var_rvalue = get_var_rvalue(var_name);
	if (var_rvalue) {
		fn = parse_term(&var_rvalue, OP_PRIO_NONE);
		if (var_rvalue[0] != '\n')
			cpuplugd_exit("parsing error at %s, position: %s\n",
				      var_name, var_rvalue);
		*p = s;
	}
	return fn;
}

struct term *parse_term(char **p, enum op_prio prio)
{
	struct term *fn, *new;
	enum operation op;
	char *s, *endptr;
	double value;
	unsigned int length, i, index;

	s = *p;
	fn = NULL;
	if (*s == '-') {
		s++;
		fn = malloc(sizeof(struct term));
		if (fn == NULL)
			goto out_error;
		if  (isdigit(*s)) {
			value = 0;
			length = 0;
			sscanf(s, "%lf%n", &value, &length);
			fn->op = OP_CONST;
			fn->value = -value;
			s += length;
		} else {
			fn->op = OP_NEG;
			fn->left = parse_term(&s, prio);
			if (fn->left == NULL)
				goto out_error;
		}
	} else if (*s == '!') {
		s++;
		fn = malloc(sizeof(struct term));
		if (fn == NULL)
			goto out_error;
		fn->op = OP_NOT;
		fn->left = parse_term(&s, prio);
		if (fn->left == NULL)
			goto out_error;
	} else if (isdigit(*s)) {
		value = 0;
		length = 0;
		sscanf(s, "%lf%n", &value, &length);
		for (i = 0; i < length; i++)
			s++;
		fn = malloc(sizeof(struct term));
		if (fn == NULL)
			goto out_error;
		fn->op = OP_CONST;
		fn->value = value;
	} else if (*s == '(') {
		s++;
		fn = parse_term(&s, OP_PRIO_NONE);
		if (fn == NULL || *s != ')')
			goto out_error;
		s++;
	} else {
		/* Check for variable name */
		fn = parse_var_term(&s);
		if (fn == NULL) {
			for (i = 0; i < sym_names_count; i++)
				if (strncmp(s, sym_names[i].name,
					    strlen(sym_names[i].name)) == 0)
					break;
			if (i >= sym_names_count)
				/* Term doesn't make sense. */
				goto out_error;
			/*
			 * Parse meminfo/vmstat/cpustat with optional history
			 * index [x]
			 */
			fn = malloc(sizeof(struct term));
			if (fn == NULL)
				goto out_error;
			fn->op = sym_names[i].symop;
			s += strlen(sym_names[i].name);
			length = 0;
			if (fn->op == OP_SYMBOL_MEMINFO ||
			    fn->op == OP_SYMBOL_VMSTAT ||
			    fn->op == OP_SYMBOL_CPUSTAT) {
				while (isalpha(s[length]) || s[length] == '_')
					length++;
				fn->proc_name = malloc(length + 1);
				if (fn->proc_name == NULL)
					goto out_error;
				strncpy(fn->proc_name, s, length);
				fn->proc_name[length] = '\0';
			}
			if (fn->op == OP_SYMBOL_MEMINFO ||
			    fn->op == OP_SYMBOL_VMSTAT ||
			    fn->op == OP_SYMBOL_CPUSTAT ||
			    fn->op == OP_SYMBOL_TIME) {
				if (s[length] == '[') {
					length++;
					if (!isdigit(s[length]))
						goto out_error;
					index = strtol(s + length, &endptr, 10);
					length = endptr - s;
					if (s[length] != ']')
						goto out_error;
					fn->index = index;
					if (history_max < index)
						history_max = index;
					length++;
				}
				s += length;
			}
		}
	}
	while (1) {
		switch (*s) {
		case '>':
			op = OP_GREATER;
			break;
		case '<':
			op = OP_LESSER;
			break;
		case '+':
			op = OP_PLUS;
			break;
		case '-':
			op = OP_MINUS;
			break;
		case '*':
			op = OP_MULT;
			break;
		case '/':
			op = OP_DIV;
			break;
		case '|':
			op = OP_OR;
			break;
		case '&':
			op = OP_AND;
			break;
		default:
			goto out;
		}
		if (prio >= op_prio_table[op])
			break;
		s++;
		new = malloc(sizeof(struct term));
		new->op = op;
		new->left = fn;
		if (new == NULL)
			goto out_error;
		new->right = parse_term(&s, op_prio_table[op]);
		if (new->right == NULL) {
			free(new);
			goto out_error;
		}
		fn = new;
	}
out:
	*p = s;
	return fn;
out_error:
	if (fn)
		free_term(fn);
	return NULL;
}

static double get_value(struct term *fn)
{
	double value = 0;
	char *procinfo;
	unsigned int history_index;

	if (fn->index <= history_current)
		history_index = history_current - fn->index;
	else
		history_index = history_max + 1 - (fn->index - history_current);

	switch (fn->op) {
	case OP_SYMBOL_MEMINFO:
		procinfo = meminfo + history_index * meminfo_size;
		value = get_proc_value(procinfo, fn->proc_name, ':');
		break;
	case OP_SYMBOL_VMSTAT:
		procinfo = vmstat + history_index * vmstat_size;
		value = get_proc_value(procinfo, fn->proc_name, ' ');
		break;
	case OP_SYMBOL_CPUSTAT:
		procinfo = cpustat + history_index * cpustat_size;
		value = get_proc_value(procinfo, fn->proc_name, ' ');
		break;
	case OP_SYMBOL_TIME:
		value = timestamps[history_index];
		break;
	default:
		cpuplugd_exit("Invalid term specified: %i\n", fn->op);
	}
	return value;
}

double eval_double(struct term *fn, struct symbols *symbols)
{
	double a, b, sum;

	switch (fn->op) {
	case OP_SYMBOL_LOADAVG:
		return symbols->loadavg;
	case OP_SYMBOL_RUNABLE:
		return symbols->runnable_proc;
	case OP_SYMBOL_CPUS:
		return symbols->onumcpus;
	case OP_SYMBOL_USER:
		return symbols->user;
	case OP_SYMBOL_NICE:
		return symbols->nice;
	case OP_SYMBOL_SYSTEM:
		return symbols->system;
	case OP_SYMBOL_IDLE:
		return symbols->idle;
	case OP_SYMBOL_IOWAIT:
		return symbols->iowait;
	case OP_SYMBOL_IRQ:
		return symbols->irq;
	case OP_SYMBOL_SOFTIRQ:
		return symbols->softirq;
	case OP_SYMBOL_STEAL:
		return symbols->steal;
	case OP_SYMBOL_GUEST:
		return symbols->guest;
	case OP_SYMBOL_GUEST_NICE:
		return symbols->guest_nice;
	case OP_SYMBOL_FREEMEM:
		return symbols->freemem;
	case OP_SYMBOL_APCR:
		return symbols->apcr;
	case OP_SYMBOL_SWAPRATE:
		return symbols->swaprate;
	case OP_SYMBOL_MEMINFO:
	case OP_SYMBOL_VMSTAT:
	case OP_SYMBOL_CPUSTAT:
	case OP_SYMBOL_TIME:
		return get_value(fn);
	case OP_CONST:
		return fn->value;
	case OP_NEG:
		return -eval_double(fn->left, symbols);
	case OP_PLUS:
		return eval_double(fn->left, symbols) +
			eval_double(fn->right, symbols);
	case OP_MINUS:
		return eval_double(fn->left, symbols) -
			eval_double(fn->right, symbols);
	case OP_MULT:
		a = eval_double(fn->left, symbols);
		b = eval_double(fn->right, symbols);
		sum = a*b;
		return sum;
		/*return eval_double(fn->left, symbols) *
			eval_double(fn->right, symbols);*/
	case OP_DIV:
		a = eval_double(fn->left, symbols);
		b = eval_double(fn->right, symbols);
		sum = a/b;
		return sum;
		/*return eval_double(fn->left, symbols) /
			eval_double(fn->right, symbols); */
	case OP_NOT:
	case OP_AND:
	case OP_OR:
	case OP_GREATER:
	case OP_LESSER:
	case VAR_LOAD:
	case VAR_RUN:
	case VAR_ONLINE:
		cpuplugd_exit("Invalid term specified: %i\n", fn->op);
	}
	return 0;
}

int eval_term(struct term *fn, struct symbols *symbols)
{
	if (fn == NULL || symbols == NULL)
		return 0.0;
	switch (fn->op) {
	case OP_NOT:
		return !eval_term(fn->left, symbols);
	case OP_OR:
		return eval_term(fn->left, symbols) == 1 ||
			eval_term(fn->right, symbols) == 1;
	case OP_AND:
		return eval_term(fn->left, symbols) == 1 &&
			eval_term(fn->right, symbols) == 1;
	case OP_GREATER:
		return eval_double(fn->left, symbols) >
			eval_double(fn->right, symbols);
	case OP_LESSER:
		return eval_double(fn->left, symbols) <
			eval_double(fn->right, symbols);
	default:
		return eval_double(fn, symbols) != 0.0;
	}
}
