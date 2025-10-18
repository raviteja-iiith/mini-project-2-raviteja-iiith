#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CUSTOMERS 25
#define NUM_OVENS 4
#define NUM_CHEFS 4
#define SOFA_CAPACITY 4

// ==================== STRUCTURES ====================
typedef struct {
    int id;
    int arrival_time;
    int thread_id;
} Customer;

typedef struct {
    int timestamp;
    char type[20];
    int id;
    char action[50];
    int for_customer_id;
} Event;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool can_sit;
    bool cake_ready;
    bool payment_accepted;
    int bake_end_time;
    int sit_time;
} CustomerSync;

typedef struct {
    int customer_id;
    int pay_time;
    bool processed;
} PaymentRequest;

typedef struct {
    int arrival_time;
    int customer_id;
} InputCustomer;

// ==================== GLOBAL VARIABLES ====================
pthread_mutex_t shop_mutex;
pthread_mutex_t sofa_mutex;
pthread_mutex_t output_mutex;
pthread_mutex_t time_mutex;

sem_t ovens;
sem_t cash_register;

int current_time = 0;
int customers_in_shop = 0;
int customers_on_sofa = 0;
bool simulation_running = true;

Customer sofa_queue[SOFA_CAPACITY];
int sofa_front = 0, sofa_rear = 0;

Customer standing_queue[MAX_CUSTOMERS];
int standing_front = 0, standing_rear = 0;

Event event_queue[10000];
int event_count = 0;

static CustomerSync customer_sync[100000];
static pthread_once_t sync_init = PTHREAD_ONCE_INIT;

static PaymentRequest payment_queue[1000];
static int payment_count = 0;
static pthread_mutex_t payment_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

// ==================== QUEUE FUNCTIONS ====================
void enqueue_sofa(Customer c) {
    sofa_queue[sofa_rear] = c;
    sofa_rear = (sofa_rear + 1) % SOFA_CAPACITY;
}

Customer dequeue_sofa() {
    Customer c = sofa_queue[sofa_front];
    sofa_front = (sofa_front + 1) % SOFA_CAPACITY;
    return c;
}

bool is_sofa_empty() {
    return sofa_front == sofa_rear;
}

void enqueue_standing(Customer c) {
    standing_queue[standing_rear] = c;
    standing_rear = (standing_rear + 1) % MAX_CUSTOMERS;
}

Customer dequeue_standing() {
    Customer c = standing_queue[standing_front];
    standing_front = (standing_front + 1) % MAX_CUSTOMERS;
    return c;
}

bool is_standing_empty() {
    return standing_front == standing_rear;
}

// ==================== UTILITY FUNCTIONS ====================
int get_current_time() {
    pthread_mutex_lock(&time_mutex);
    int time = current_time;
    pthread_mutex_unlock(&time_mutex);
    return time;
}

void add_event(int timestamp, const char* type, int id, const char* action, int for_customer_id) {
    pthread_mutex_lock(&output_mutex);
    event_queue[event_count].timestamp = timestamp;
    strcpy(event_queue[event_count].type, type);
    event_queue[event_count].id = id;
    strcpy(event_queue[event_count].action, action);
    event_queue[event_count].for_customer_id = for_customer_id;
    event_count++;
    pthread_mutex_unlock(&output_mutex);
}

int compare_events(const void* a, const void* b) {
    Event* e1 = (Event*)a;
    Event* e2 = (Event*)b;
    
    if (e1->timestamp != e2->timestamp) {
        return e1->timestamp - e2->timestamp;
    }
    
    int get_priority(const Event* e) {
        if (strcmp(e->type, "Customer") == 0) {
            if (strcmp(e->action, "enters") == 0) return 0;
            if (strcmp(e->action, "sits") == 0) return 1;
            if (strcmp(e->action, "requests cake") == 0) return 2;
            if (strcmp(e->action, "pays") == 0) return 4;
            if (strcmp(e->action, "leaves") == 0) return 6;
        } else {
            if (strstr(e->action, "bakes") != NULL) return 3;
            if (strstr(e->action, "accepts payment") != NULL) return 5;
        }
        return 99;
    }
    
    int p1 = get_priority(e1);
    int p2 = get_priority(e2);
    
    if (p1 != p2) return p1 - p2;
    return e1->id - e2->id;
}

void print_events() {
    qsort(event_queue, event_count, sizeof(Event), compare_events);
    
    for (int i = 0; i < event_count; i++) {
        if (event_queue[i].for_customer_id > 0) {
            printf("%d %s %d %s %d\n",
                   event_queue[i].timestamp,
                   event_queue[i].type,
                   event_queue[i].id,
                   event_queue[i].action,
                   event_queue[i].for_customer_id);
        } else {
            printf("%d %s %d %s\n",
                   event_queue[i].timestamp,
                   event_queue[i].type,
                   event_queue[i].id,
                   event_queue[i].action);
        }
    }
}

void init_bakery() {
    pthread_mutex_init(&shop_mutex, NULL);
    pthread_mutex_init(&sofa_mutex, NULL);
    pthread_mutex_init(&output_mutex, NULL);
    pthread_mutex_init(&time_mutex, NULL);
    
    sem_init(&ovens, 0, NUM_OVENS);
    sem_init(&cash_register, 0, 1);
    
    current_time = 0;
    customers_in_shop = 0;
    customers_on_sofa = 0;
    simulation_running = true;
    
    sofa_front = sofa_rear = 0;
    standing_front = standing_rear = 0;
    event_count = 0;
}

void cleanup_bakery() {
    pthread_mutex_destroy(&shop_mutex);
    pthread_mutex_destroy(&sofa_mutex);
    pthread_mutex_destroy(&output_mutex);
    pthread_mutex_destroy(&time_mutex);
    
    sem_destroy(&ovens);
    sem_destroy(&cash_register);
}

// ==================== CUSTOMER SYNC FUNCTIONS ====================
void init_customer_sync() {
    for (int i = 0; i < 100000; i++) {
        pthread_mutex_init(&customer_sync[i].mutex, NULL);
        pthread_cond_init(&customer_sync[i].cond, NULL);
        customer_sync[i].can_sit = false;
        customer_sync[i].cake_ready = false;
        customer_sync[i].payment_accepted = false;
        customer_sync[i].bake_end_time = -1;
        customer_sync[i].sit_time = -1;
    }
}

void notify_can_sit(int customer_id, int when_can_sit) {
    pthread_mutex_lock(&customer_sync[customer_id % 100000].mutex);
    customer_sync[customer_id % 100000].can_sit = true;
    customer_sync[customer_id % 100000].sit_time = when_can_sit;
    pthread_cond_signal(&customer_sync[customer_id % 100000].cond);
    pthread_mutex_unlock(&customer_sync[customer_id % 100000].mutex);
}

void signal_cake_ready(int customer_id, int bake_end_time) {
    pthread_mutex_lock(&customer_sync[customer_id % 100000].mutex);
    customer_sync[customer_id % 100000].cake_ready = true;
    customer_sync[customer_id % 100000].bake_end_time = bake_end_time;
    pthread_cond_signal(&customer_sync[customer_id % 100000].cond);
    pthread_mutex_unlock(&customer_sync[customer_id % 100000].mutex);
}

void signal_payment_accepted(int customer_id, int acceptance_end_time) {
    pthread_mutex_lock(&customer_sync[customer_id % 100000].mutex);
    customer_sync[customer_id % 100000].payment_accepted = true;
    customer_sync[customer_id % 100000].bake_end_time = acceptance_end_time;
    pthread_cond_signal(&customer_sync[customer_id % 100000].cond);
    pthread_mutex_unlock(&customer_sync[customer_id % 100000].mutex);
}

//############## LLM Generated Code Begins ##############
void add_payment_request(int customer_id, int pay_time) {
    pthread_mutex_lock(&payment_queue_mutex);
    payment_queue[payment_count].customer_id = customer_id;
    payment_queue[payment_count].pay_time = pay_time;
    payment_queue[payment_count].processed = false;
    payment_count++;
    pthread_mutex_unlock(&payment_queue_mutex);
}
//############## LLM Generated Code Ends ################

bool get_next_payment(int* customer_id, int* pay_time) {
    pthread_mutex_lock(&payment_queue_mutex);
    int current = get_current_time();
    
    int earliest_idx = -1;
    int earliest_time = current + 1000;
    
    for (int i = 0; i < payment_count; i++) {
        if (!payment_queue[i].processed && 
            payment_queue[i].pay_time <= current &&
            payment_queue[i].pay_time < earliest_time) {
            earliest_time = payment_queue[i].pay_time;
            earliest_idx = i;
        }
    }
    
    if (earliest_idx >= 0) {
        *customer_id = payment_queue[earliest_idx].customer_id;
        *pay_time = payment_queue[earliest_idx].pay_time;
        payment_queue[earliest_idx].processed = true;
        pthread_mutex_unlock(&payment_queue_mutex);
        return true;
    }
    
    pthread_mutex_unlock(&payment_queue_mutex);
    return false;
}

// ==================== CUSTOMER THREAD ====================
void* customer_thread(void* arg) {
    Customer* customer = (Customer*)arg;
    int id = customer->id;
    int arrival_time = customer->arrival_time;
    
    pthread_once(&sync_init, init_customer_sync);
    
    while (get_current_time() < arrival_time) {
        usleep(10000);
    }
    
    pthread_mutex_lock(&shop_mutex);
    if (customers_in_shop >= MAX_CUSTOMERS) {
        pthread_mutex_unlock(&shop_mutex);
        free(customer);
        return NULL;
    }
    customers_in_shop++;
    pthread_mutex_unlock(&shop_mutex);
    
    int enter_time = get_current_time();
    add_event(enter_time, "Customer", id, "enters", 0);
    
    bool must_stand = false;
    pthread_mutex_lock(&sofa_mutex);
    if (customers_on_sofa < SOFA_CAPACITY) {
        customers_on_sofa++;
        customer_sync[id % 100000].can_sit = true;
        customer_sync[id % 100000].sit_time = enter_time + 1;
    } else {
        must_stand = true;
        enqueue_standing(*customer);
    }
    pthread_mutex_unlock(&sofa_mutex);
    
    if (must_stand) {
        pthread_mutex_lock(&customer_sync[id % 100000].mutex);
        while (!customer_sync[id % 100000].can_sit) {
            pthread_cond_wait(&customer_sync[id % 100000].cond, 
                            &customer_sync[id % 100000].mutex);
        }
        pthread_mutex_unlock(&customer_sync[id % 100000].mutex);
    }
    
    int sit_time = customer_sync[id % 100000].sit_time;
    add_event(sit_time, "Customer", id, "sits", 0);
    
    int request_time = sit_time + 1;
    
    pthread_mutex_lock(&sofa_mutex);
    Customer request_customer = *customer;
    request_customer.arrival_time = request_time;
    enqueue_sofa(request_customer);
    pthread_mutex_unlock(&sofa_mutex);
    
    add_event(request_time, "Customer", id, "requests cake", 0);
    
    pthread_mutex_lock(&customer_sync[id % 100000].mutex);
    while (!customer_sync[id % 100000].cake_ready) {
        pthread_cond_wait(&customer_sync[id % 100000].cond, 
                        &customer_sync[id % 100000].mutex);
    }
    int bake_end_time = customer_sync[id % 100000].bake_end_time;
    pthread_mutex_unlock(&customer_sync[id % 100000].mutex);
    
    add_event(bake_end_time, "Customer", id, "pays", 0);
    
    pthread_mutex_lock(&customer_sync[id % 100000].mutex);
    while (!customer_sync[id % 100000].payment_accepted) {
        pthread_cond_wait(&customer_sync[id % 100000].cond, 
                        &customer_sync[id % 100000].mutex);
    }
    int acceptance_end_time = customer_sync[id % 100000].bake_end_time;
    pthread_mutex_unlock(&customer_sync[id % 100000].mutex);
    
    add_event(acceptance_end_time, "Customer", id, "leaves", 0);
    
    int leave_time = acceptance_end_time;
    pthread_mutex_lock(&sofa_mutex);
    customers_on_sofa--;
    if (!is_standing_empty()) {
        Customer next = dequeue_standing();
        customers_on_sofa++;
        pthread_mutex_unlock(&sofa_mutex);
        notify_can_sit(next.id, leave_time);
    } else {
        pthread_mutex_unlock(&sofa_mutex);
    }
    
    pthread_mutex_lock(&shop_mutex);
    customers_in_shop--;
    pthread_mutex_unlock(&shop_mutex);
    
    free(customer);
    return NULL;
}

// ==================== CHEF THREAD ====================
void* chef_thread(void* arg) {
    int chef_id = *((int*)arg);
    
    while (simulation_running || customers_in_shop > 0) {
        bool did_work = false;
        
        int customer_to_pay, pay_time;
        if (get_next_payment(&customer_to_pay, &pay_time)) {
            int accept_start = pay_time + 1;
            while (get_current_time() < accept_start) {
                usleep(10000);
            }
            
            sem_wait(&cash_register);
            
            int actual_start = get_current_time();
            add_event(actual_start, "Chef", chef_id, "accepts payment for customer", customer_to_pay);
            
            int end_time = actual_start + 2;
            while (get_current_time() < end_time) {
                usleep(10000);
            }
            
            sem_post(&cash_register);
            
            signal_payment_accepted(customer_to_pay, get_current_time());
            did_work = true;
            continue;
        }
        
        pthread_mutex_lock(&sofa_mutex);
        bool has_customer = !is_sofa_empty();
        pthread_mutex_unlock(&sofa_mutex);
        
        if (has_customer) {
            if (sem_trywait(&ovens) == 0) {
                pthread_mutex_lock(&sofa_mutex);
                if (!is_sofa_empty()) {
                    Customer customer = dequeue_sofa();
                    int customer_id = customer.id;
                    int request_time = customer.arrival_time;
                    pthread_mutex_unlock(&sofa_mutex);
                    
                    int bake_start = request_time + 1;
                    while (get_current_time() < bake_start) {
                        usleep(10000);
                    }
                    
                    int actual_start = get_current_time();
                    add_event(actual_start, "Chef", chef_id, "bakes for customer", customer_id);
                    
                    int bake_end = actual_start + 2;
                    while (get_current_time() < bake_end) {
                        usleep(10000);
                    }
                    
                    int bake_end_time = get_current_time();
                    signal_cake_ready(customer_id, bake_end_time);
                    add_payment_request(customer_id, bake_end_time);
                    
                    sem_post(&ovens);
                    did_work = true;
                } else {
                    pthread_mutex_unlock(&sofa_mutex);
                    sem_post(&ovens);
                }
            }
        }
        
        if (!did_work) {
            usleep(50000);
        }
    }
    
    free(arg);
    return NULL;
}

// ==================== TIME SIMULATOR THREAD ====================
void* time_simulator(void* arg) {
    int* max_time = (int*)arg;
    
    for (int t = 0; t <= *max_time + 200; t++) {
        pthread_mutex_lock(&time_mutex);
        current_time = t;
        pthread_mutex_unlock(&time_mutex);
        usleep(100000); // 0.1 second per time unit
    }
    
    return NULL;
}

// ==================== MAIN ====================
int main() {
    InputCustomer inputs[1000];
    int input_count = 0;
    int max_time = 0;
    
    char line[100];
    while (fgets(line, sizeof(line), stdin)) {
        if (strstr(line, "<EOF>") != NULL) break;
        
        int time, id;
        char customer_str[20];
        if (sscanf(line, "%d %s %d", &time, customer_str, &id) == 3) {
            inputs[input_count].arrival_time = time;
            inputs[input_count].customer_id = id;
            input_count++;
            if (time > max_time) max_time = time;
        }
    }
    
    if (input_count == 0) {
        fprintf(stderr, "No customers\n");
        return 1;
    }
    
    init_bakery();
    
    pthread_t time_thread;
    pthread_create(&time_thread, NULL, time_simulator, &max_time);
    
    pthread_t chef_threads[NUM_CHEFS];
    for (int i = 0; i < NUM_CHEFS; i++) {
        int* chef_id = malloc(sizeof(int));
        *chef_id = i + 1;
        pthread_create(&chef_threads[i], NULL, chef_thread, chef_id);
    }
    
    pthread_t customer_threads[1000];
    for (int i = 0; i < input_count; i++) {
        Customer* customer = malloc(sizeof(Customer));
        customer->id = inputs[i].customer_id;
        customer->arrival_time = inputs[i].arrival_time;
        customer->thread_id = i;
        pthread_create(&customer_threads[i], NULL, customer_thread, customer);
    }
    
    for (int i = 0; i < input_count; i++) {
        pthread_join(customer_threads[i], NULL);
    }
    
    simulation_running = false;
    
    for (int i = 0; i < NUM_CHEFS; i++) {
        pthread_join(chef_threads[i], NULL);
    }
    
    pthread_cancel(time_thread);
    pthread_join(time_thread, NULL);
    
    print_events();
    cleanup_bakery();
    
    return 0;
}