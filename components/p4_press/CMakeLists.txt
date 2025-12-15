idf_component_register(
    SRCS "p4_press.c"
    INCLUDE_DIRS "include"
    REQUIRES p4_board p4_ctaphid
    PRIV_REQUIRES freertos
)
