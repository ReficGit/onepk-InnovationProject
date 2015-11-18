/*
 * datapath_util.h
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

char *
get_interface ();

char *
get_protocol ();

int
parse_options_datapath (int argc, char *argv[]);

char *
get_usage_required_options_datapath (void);

char *
get_usage_optional_options_datapath (void);
