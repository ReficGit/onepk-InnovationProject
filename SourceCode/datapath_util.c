/*
 * datapath_util.c
 *
 * Copyright (c) 2010-2013 by Cisco Systems, Inc.
 *
 * THIS SAMPLE CODE IS PROVIDED "AS IS" WITHOUT ANY EXPRESS OR IMPLIED WARRANTY
 * BY CISCO SOLELY FOR THE PURPOSE of PROVIDING PROGRAMMING EXAMPLES.
 * CISCO SHALL NOT BE HELD LIABLE FOR ANY USE OF THE SAMPLE CODE IN ANY
 * APPLICATION.
 *
 * Redistribution and use of the sample code, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * Redistributions of source code must retain the above disclaimer.
 */

#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "session_element_util.h"

#include "include/datapath_util.h"

/*
 * This is a utility file with helper funtions for DatapathTutorial.c
 */

static char *interface;
static char *protocol = "256";


char *
get_interface ()
{
	return interface;
}

char *
get_protocol ()
{
	return protocol;
}



/**
 * Parses options from the command line, or, if none are supplied, from a
 * properties file. Parsed options will be referenced in static variables.
 *
 * This version of parse_options() includes options specific to the
 * Datapath Tutorial.
 *
 * @param [in] argc  The number of arguments
 * @param [in] argv  The argument vector
 * @return -1  An error occurred while parsing.
 *          0  Parsing completed successfully.
 *          1  One or more required options were missing.
 */
int
parse_options_datapath (int argc, char *argv[])
{
	static const struct option options[] = {
		{ "interface",  required_argument,  0,  'i' },
		{ "protocol",   required_argument,  0,  'p' },
		{0}
	};

	int c;
	int option_index;

	if (argc <= 1) {    /* No additional command-line arguments were given. */
		read_file(argv[0], "./tutorial.properties", &argc, &argv);
	}

	opterr = 0;
	optind = 0;

	/*
	 * options:
	 *       -i, --interface <interface>
	 *       -r, --protocol <protocol>
	 *       -c, --action <packet action>
	 */
	while (1) {
		c = getopt_long(argc, argv, "-i:p:", options, &option_index);
		if (c == -1) break;

		switch (c) {
			case 'i': interface = optarg;
					  break;
			case 'p': protocol = optarg;
					  break;
			default: break;
		}
	}

	if (!interface) {
		return 1;
	}
	return parse_options(argc, argv);
}

/**
 * Gets the required options for running this application.
 *
 * This version of get_usage_required_options() gets options specific to the
 * Datapath Tutorial.
 *
 * @return The required options
 */
char *
get_usage_required_options_datapath (void)
{
	return
		"-i <interface>";
}

/**
 * Gets the optional options for running this application.
 *
 * This version of get_usage_optional_options() gets options specific to the
 * Datapath Tutorial.
 *
 * @return The optional options
 */
char *
get_usage_optional_options_datapath (void)
{
	return
		"[-p <protocol>]";
}
