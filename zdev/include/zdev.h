/*
 * zdev - Minimal header file containing generic definitions utilized by
 * zdev-tools.
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZDEV_H
#define ZDEV_H

/**
 * Currently zdev supports 10 sites. Which means, zdev support 10 different
 * set of attributes which are specific to each site. When the user does
 * not provide any site information, the common set will be used which is
 * not specific to any site. So, total we have 11 persistent attribute sets
 * Where,
 * 0- 9: Site specific attributes
 * 10: Common attributes which do not belong to any sites
 */

#define NUM_SITES 11
#define NUM_USER_SITES (NUM_SITES - 1)
#define SITE_FALLBACK NUM_USER_SITES

/* Helper to find the availability of site-configuration */
#define dev_site_configured(dev, x) (dev->site_specific[(x)].exists && \
				     !dev->site_specific[(x)].deconfigured)
#endif /* ZDEV_H */
