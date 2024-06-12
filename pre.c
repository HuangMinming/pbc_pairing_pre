#include <stdio.h>
#include "pbc.h"

#define SERV_PORT 6666
#define MAX_USERID 1024
#define MAX_FILEID 1024
#define MAX_MSG 4096
pairing_t pairing;
element_t g;
element_t Z;


void pairing_init()
{

    // sgx_printf("****start\n");
    // Initialize pairing
    char param_str[] = "type a\n"
                       "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
                       "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
                       "r 730750818665451621361119245571504901405976559617\n"
                       "exp2 159\n"
                       "exp1 107\n"
                       "sign1 1\n"
                       "sign0 1";
    pbc_param_t par;
    pbc_param_init_set_str(par, param_str);
    pairing_init_pbc_param(pairing, par);
}

void pairing_generate_g_Z()
{

    // Initialize elements
    element_init_G1(g, pairing);

    element_random(g);

    element_init_GT(Z, pairing);

    pairing_apply(Z, g, g, pairing); // e(g,g)
}

int Key_Generation(element_t *ptr_a1, element_t *ptr_a2, element_t *ptr_Z_a1, element_t *ptr_g_a2)
{
    element_random(*ptr_a1);
    element_random(*ptr_a2);

    element_pow_zn(*ptr_Z_a1, Z, *ptr_a1);
    element_pow_zn(*ptr_g_a2, g, *ptr_a2);

    element_printf("*ptr_a1 = %B\n", *ptr_a1);
    element_printf("*ptr_a2 = %B\n", *ptr_a2);
    element_printf("*ptr_Z_a1 = %B\n", *ptr_Z_a1);
    element_printf("*ptr_g_a2 = %B\n", *ptr_g_a2);
    return 0;
}

/*
rkA→B = g^a1^b2 ∈ G1
*/
int Re_Encryption_Key_Generation(element_t *ptr_a1, 
                                   element_t *ptr_g_b2, 
                                   element_t *ptr_rk_A_B)
{

    element_pow_zn(*ptr_rk_A_B, *ptr_g_b2,  *ptr_a1);

    element_printf("*ptr_rk_A_B = %B\n", *ptr_rk_A_B);
    return 0;
}

int First_Level_Encryption(element_t *ptr_m, 
                             element_t *ptr_Z_a1, 
                             element_t *ptr_a2, 
                             element_t *ptr_Z_a1_k, 
                             element_t *ptr_m_Z_k, 
                             element_t *ptr_Z_a2_k)
{
    element_t k, Z_k;
    element_init_Zr(k, pairing);
    element_init_GT(Z_k, pairing);
    element_random(k);


    element_pow_zn(ptr_Z_a1_k, *ptr_Z_a1, k);
    element_pow_zn(Z_k, Z, k);
    element_mul(ptr_m_Z_k, *ptr_m, Z_k);

    element_t Z_a2;
    element_init_GT(Z_a2, pairing);
    

    element_pow_zn(Z_a2, Z, *ptr_a2);
    element_pow_zn(*ptr_Z_a2_k, Z_a2, k);

    element_printf("*ptr_Z_a1_k = %B\n", *ptr_Z_a1_k);
    element_printf("*ptr_m_Z_k = %B\n", *ptr_m_Z_k);
    element_printf("*ptr_Z_a2_k = %B\n", *ptr_Z_a2_k);

    element_clear(k);
    element_clear(Z_k);
    element_clear(Z_a2);
    return 0;
}

int Second_Level_Encryption(element_t *ptr_m,
                 element_t *ptr_Z_a1,
                 element_t *ptr_g_k,
                 element_t *ptr_m_Z_a1_k)
{
    element_t k, Z_a1_k;
    element_init_Zr(k, pairing);
    element_init_GT(Z_a1_k, pairing);
    element_random(k);

    element_pow_zn(*ptr_g_k, g, k);
    element_pow_zn(Z_a1_k, *ptr_Z_a1, k);
    element_mul(*ptr_m_Z_a1_k, *ptr_m, Z_a1_k);

    element_printf("*ptr_g_k = %B\n", *ptr_g_k);
    element_printf("*ptr_m_Z_a1_k = %B\n", *ptr_m_Z_a1_k);

    element_clear(k);
    element_clear(Z_a1_k);
    return 0;
}


int First_Level_Decryption(element_t *ptr_Z_a1_k,
                             element_t *ptr_m_Z_k, 
                             element_t *ptr_Z_a2_k, 
                             element_t *ptr_a1, 
                             element_t *ptr_a2)
{

    element_t a1_invert, a2_invert, alpha_a1_invert, alpha_a2_invert;
    element_t beta_alpha_a1_invert, beta_alpha_a2_invert;

    

    element_init_Zr(a1_invert, pairing);
    element_init_Zr(a2_invert, pairing);
    element_init_GT(alpha_a1_invert, pairing);
    element_init_GT(alpha_a2_invert, pairing);
    element_init_GT(beta_alpha_a1_invert, pairing);
    element_init_GT(beta_alpha_a2_invert, pairing);

    element_invert(a1_invert, *ptr_a1);
    element_invert(a2_invert, *ptr_a2);

    element_pow_zn(alpha_a1_invert, *ptr_Z_a1_k, a1_invert);
    element_pow_zn(alpha_a2_invert, *ptr_Z_a2_k, a2_invert);

    element_div(beta_alpha_a1_invert, *ptr_m_Z_k, alpha_a1_invert);
    element_div(beta_alpha_a2_invert, *ptr_m_Z_k, alpha_a2_invert);

    element_printf("beta_alpha_a1_invert = %B\n", beta_alpha_a1_invert);
    element_printf("beta_alpha_a2_invert = %B\n", beta_alpha_a2_invert);

    element_clear(a1_invert);
    element_clear(a2_invert);
    element_clear(alpha_a1_invert);
    element_clear(alpha_a2_invert);
    element_clear(beta_alpha_a1_invert);
    element_clear(beta_alpha_a2_invert);

    return 0;
}

int Second_Level_Decryption(element_t *ptr_g_k, 
                              element_t *ptr_m_Z_a1_k, 
                              element_t *ptr_a1)
{

    element_t pair_alpha_g, pair_alpha_g_a1, beta_pair_alpha_g_a1;

    

    element_init_GT(pair_alpha_g, pairing);
    element_init_GT(pair_alpha_g_a1, pairing);
    element_init_GT(beta_pair_alpha_g_a1, pairing);

    pairing_apply(pair_alpha_g, *ptr_g_k, g, pairing);
    element_pow_zn(pair_alpha_g_a1, pair_alpha_g, *ptr_a1);
    element_div(beta_pair_alpha_g_a1, *ptr_m_Z_a1_k, pair_alpha_g_a1);


    element_printf("beta_pair_alpha_g_a1 = %B\n", beta_pair_alpha_g_a1);

    element_clear(pair_alpha_g);
    element_clear(pair_alpha_g_a1);
    element_clear(beta_pair_alpha_g_a1);

    return 0;
}

int B_Decryption(
    element_t *ptr_m_Z_a1_k, 
    element_t *ptr_Z_b2_a1_k, 
    element_t *ptr_b2) 
{


    element_t b2_invert, alpha_b2_invert, beta_alpha_b2_invert;

    

    element_init_Zr(b2_invert, pairing);
    element_init_GT(alpha_b2_invert, pairing);
    element_init_GT(beta_alpha_b2_invert, pairing);

    element_invert(b2_invert, *ptr_b2);
    element_pow_zn(alpha_b2_invert, *ptr_Z_b2_a1_k, b2_invert);
    element_div(beta_alpha_b2_invert, *ptr_m_Z_a1_k, alpha_b2_invert);

    element_printf("beta_alpha_b2_invert = %B\n", beta_alpha_b2_invert);
    element_clear(b2_invert);
    element_clear(alpha_b2_invert);
    element_clear(beta_alpha_b2_invert);
    
    return 0;

}

void pairing_destroy()
{
    element_clear(g);
    element_clear(Z);
    pairing_clear(pairing);
}

int main(int argc, char *argv[])
{

    pairing_init();
    pairing_generate_g_Z();
    

    element_t a1, a2, Z_a1, g_a2;
    element_init_Zr(a1, pairing);
    element_init_Zr(a2, pairing);
    element_init_GT(Z_a1, pairing);
    element_init_G1(g_a2, pairing);
    Key_Generation(&a1, &a2, &Z_a1, &g_a2);

    element_printf("a1 = %B\n", a1);
    element_printf("a2 = %B\n", a2);
    element_printf("Z_a1 = %B\n", Z_a1);
    element_printf("g_a2 = %B\n", g_a2);

    element_t b1, b2, Z_b1, g_b2;
    element_init_Zr(b1, pairing);
    element_init_Zr(b2, pairing);
    element_init_GT(Z_b1, pairing);
    element_init_G1(g_b2, pairing);
    Key_Generation(&b1, &b2, &Z_b1, &g_b2);

    element_printf("b1 = %B\n", b1);
    element_printf("b2 = %B\n", b2);
    element_printf("Z_b1 = %B\n", Z_b1);
    element_printf("g_b2 = %B\n", g_b2);

    element_t rk_A_B;
    element_init_G1(rk_A_B, pairing);
    Re_Encryption_Key_Generation(&a1, &g_b2, &rk_A_B);
    element_printf("rk_A_B = %B\n", rk_A_B);


    element_t m;
    element_init_GT(m, pairing);
    element_random(m);
    element_printf("m = %B\n", m);


    element_t Z_a1_k, m_Z_k, Z_a2_k;
    element_init_GT(Z_a1_k, pairing);
    element_init_GT(m_Z_k, pairing);
    element_init_GT(Z_a2_k, pairing);

    First_Level_Encryption(&m, &Z_a1, &a2, &Z_a1_k, &m_Z_k, &Z_a2_k);

    element_printf("Z_a1_k = %B\n", Z_a1_k);
    element_printf("m_Z_k = %B\n", m_Z_k);
    element_printf("Z_a2_k = %B\n", Z_a2_k);

    element_t g_k, m_Z_a1_k;

    element_init_G1(g_k, pairing);
    element_init_GT(m_Z_a1_k, pairing);

    Second_Level_Encryption(&m, &Z_a1, &g_k, &m_Z_a1_k);
    element_printf("g_k = %B\n", g_k);
    element_printf("m_Z_a1_k = %B\n", m_Z_a1_k);

    element_t  Z_b2_a1_k;
    element_init_GT(Z_b2_a1_k, pairing);
    pairing_apply(Z_b2_a1_k, g_k, rk_A_B, pairing);

    element_printf("Z_b2_a1_k = %B\n", Z_b2_a1_k);


    First_Level_Decryption(&Z_a1_k, &m_Z_k, &Z_a2_k, &a1, &a2);

    Second_Level_Decryption(&g_k, &m_Z_a1_k, &a1);

    B_Decryption(&m_Z_a1_k, &Z_b2_a1_k, &b2);
    element_clear(a1);
    element_clear(a2);
    element_clear(Z_a1);
    element_clear(g_a2);
    element_clear(b1);
    element_clear(b2);
    element_clear(Z_b1);
    element_clear(g_b2);
    element_clear(rk_A_B);
    element_clear(m);
    element_clear(Z_a1_k);
    element_clear(m_Z_k);
    element_clear(Z_a2_k);
    element_clear(g_k);
    element_clear(m_Z_a1_k);
    element_clear(Z_b2_a1_k);
    pairing_destroy();
    return 0;

}